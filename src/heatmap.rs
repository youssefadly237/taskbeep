use std::{
    collections::HashMap,
    env,
    io::{self, IsTerminal},
};

use time::{Date, Duration, Month, OffsetDateTime, UtcOffset};

use crate::{
    error::{Result, TaskBeepError},
    stats::StatsEntry,
    utils::{
        DurationDisplay, HeatmapAccent, day_label, heatmap_cell_level, heatmap_legend_levels,
        local_date_from_ms, sunday_end_of_week, sunday_start_of_week,
    },
};

const DAY_LABEL_WIDTH: usize = 4;
const CELL_WIDTH: usize = 2;

#[derive(Debug, Clone, Copy)]
pub struct HeatCell {
    pub date: Date,
    pub in_window: bool,
    pub working_ms: u64,
}

#[derive(Debug)]
pub struct HeatGrid {
    pub weeks: usize,
    pub max_working_ms: u64,
    pub total_working_ms: u64,
    pub cells: Vec<HeatCell>,
}

#[derive(Debug, Clone, Default)]
#[cfg(feature = "ui")]
pub struct HeatDayStats {
    pub working_ms: u64,
    pub wasting_ms: u64,
    pub sessions: u32,
    pub by_topic: HashMap<String, u64>,
}

#[derive(Debug)]
pub struct HeatAggregation {
    pub grid: HeatGrid,
    #[cfg(feature = "ui")]
    pub day_stats: HashMap<Date, HeatDayStats>,
    #[cfg(feature = "ui")]
    pub per_topic_days: HashMap<String, HashMap<Date, bool>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColorMode {
    Ansi,
    Plain,
}

impl ColorMode {
    fn detect() -> Self {
        let no_color = env::var_os("NO_COLOR").is_some();
        let dumb_terminal = env::var("TERM")
            .map(|term| term.eq_ignore_ascii_case("dumb"))
            .unwrap_or(false);

        if io::stdout().is_terminal() && !no_color && !dumb_terminal {
            Self::Ansi
        } else {
            Self::Plain
        }
    }
}

pub fn render_stats_heatmap(entries: &[StatsEntry], year: Option<i32>) -> Result<String> {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let today = OffsetDateTime::now_utc().to_offset(offset).date();
    let mut inferred_year: Option<i32> = None;
    let mut window_start: Option<Date> = None;
    let mut window_end: Option<Date> = None;
    for entry in entries {
        if let Ok(date) = local_date_from_ms(entry.start_time_ms, offset) {
            inferred_year = Some(inferred_year.map_or(date.year(), |y| y.max(date.year())));
            window_start = Some(window_start.map_or(date, |cur| cur.min(date)));
            window_end = Some(window_end.map_or(date, |cur| cur.max(date)));
        }
    }

    let year = year.or(inferred_year).unwrap_or(today.year());
    let heatmap = if let (Some(start), Some(end)) = (window_start, window_end) {
        build_heat_grid(entries, start, end, offset)?
    } else {
        build_heatmap(entries, year, offset)?
    };

    Ok(render_heatmap(
        &heatmap,
        ColorMode::detect(),
        HeatmapAccent::from_env(),
    ))
}

/// Build the Sunday-aligned heatmap grid for an arbitrary window.
///
/// Only working entries contribute to `working_ms`; wasting entries are
/// ignored.  Cells outside `[window_start, window_end]` have `in_window =
/// false` and exist only to pad the grid to full weeks.
pub fn build_heat_grid(
    entries: &[StatsEntry],
    window_start: Date,
    window_end: Date,
    offset: UtcOffset,
) -> Result<HeatGrid> {
    Ok(build_heat_aggregation(entries, window_start, window_end, offset)?.grid)
}

/// Build all heatmap-related aggregates in a single pass over entries.
pub fn build_heat_aggregation(
    entries: &[StatsEntry],
    window_start: Date,
    window_end: Date,
    offset: UtcOffset,
) -> Result<HeatAggregation> {
    let grid_start = sunday_start_of_week(window_start);
    let grid_end = sunday_end_of_week(window_end);
    let total_days = (grid_end - grid_start).whole_days() as usize + 1;
    let weeks = total_days / 7;

    let mut by_day: HashMap<Date, u64> = HashMap::new();
    #[cfg(feature = "ui")]
    let mut day_stats: HashMap<Date, HeatDayStats> = HashMap::new();
    #[cfg(feature = "ui")]
    let mut per_topic_days: HashMap<String, HashMap<Date, bool>> = HashMap::new();

    for entry in entries {
        let date = local_date_from_ms(entry.start_time_ms, offset)?;
        if date < window_start || date > window_end {
            continue;
        }

        if entry.was_working {
            *by_day.entry(date).or_insert(0) += entry.duration_ms;
        }

        #[cfg(feature = "ui")]
        {
            let stats = day_stats.entry(date).or_default();
            stats.sessions += 1;
            if entry.was_working {
                stats.working_ms += entry.duration_ms;
                *stats.by_topic.entry(entry.topic.clone()).or_insert(0) += entry.duration_ms;
                per_topic_days
                    .entry(entry.topic.clone())
                    .or_default()
                    .insert(date, true);
            } else {
                stats.wasting_ms += entry.duration_ms;
            }
        }
    }

    let mut cells = Vec::with_capacity(total_days);
    let mut max_working_ms = 0u64;
    let mut total_working_ms = 0u64;
    for day_index in 0..total_days {
        let date = grid_start + Duration::days(day_index as i64);
        let in_window = date >= window_start && date <= window_end;
        let working_ms = if in_window {
            by_day.get(&date).copied().unwrap_or(0)
        } else {
            0
        };
        if in_window {
            max_working_ms = max_working_ms.max(working_ms);
            total_working_ms += working_ms;
        }
        cells.push(HeatCell {
            date,
            in_window,
            working_ms,
        });
    }

    Ok(HeatAggregation {
        grid: HeatGrid {
            weeks,
            max_working_ms,
            total_working_ms,
            cells,
        },
        #[cfg(feature = "ui")]
        day_stats,
        #[cfg(feature = "ui")]
        per_topic_days,
    })
}

fn build_heatmap(entries: &[StatsEntry], year: i32, offset: UtcOffset) -> Result<HeatGrid> {
    let jan_1 = Date::from_calendar_date(year, Month::January, 1)
        .map_err(|e| TaskBeepError::StatsError(format!("invalid year {year}: {e}")))?;
    let dec_31 = Date::from_calendar_date(year, Month::December, 31)
        .map_err(|e| TaskBeepError::StatsError(format!("invalid year {year}: {e}")))?;
    build_heat_grid(entries, jan_1, dec_31, offset)
}

fn render_heatmap(data: &HeatGrid, color_mode: ColorMode, accent: HeatmapAccent) -> String {
    let mut output = String::new();
    output.push_str(&render_month_labels(data));
    output.push('\n');

    for row in 0..7 {
        output.push_str(day_label(row));
        for week in 0..data.weeks {
            let cell = data.cells[week * 7 + row];
            output.push_str(&render_cell(cell, data.max_working_ms, color_mode, accent));
        }
        output.push('\n');
    }

    output.push('\n');
    output.push_str(&render_legend(data, color_mode, accent));
    output.push('\n');
    output
}

fn render_month_labels(data: &HeatGrid) -> String {
    let pairs: Vec<(Date, bool)> = data.cells.iter().map(|c| (c.date, c.in_window)).collect();
    crate::utils::month_label_chars(&pairs, data.weeks, DAY_LABEL_WIDTH, CELL_WIDTH)
}

fn render_legend(data: &HeatGrid, color_mode: ColorMode, accent: HeatmapAccent) -> String {
    let mut legend = String::new();
    legend.push_str("Less ");
    for level in heatmap_legend_levels(data.max_working_ms) {
        legend.push_str(&render_level(level, color_mode, accent));
    }
    legend.push_str("More");
    legend.push_str(&format!(
        "  Visible working time: {}",
        DurationDisplay(data.total_working_ms)
    ));
    legend
}

fn render_cell(
    cell: HeatCell,
    max_working_ms: u64,
    color_mode: ColorMode,
    accent: HeatmapAccent,
) -> String {
    let Some(level) = heatmap_cell_level(cell.working_ms, max_working_ms, cell.in_window) else {
        return "  ".to_string();
    };
    render_level(level, color_mode, accent)
}

fn render_level(level: u8, color_mode: ColorMode, accent: HeatmapAccent) -> String {
    match color_mode {
        ColorMode::Plain => plain_cell(level),
        ColorMode::Ansi => ansi_cell(level, accent),
    }
}

fn plain_cell(level: u8) -> String {
    let glyph = match level {
        0 => '·',
        1 => '░',
        2 => '▒',
        3 => '▓',
        _ => '█',
    };
    format!("{} ", glyph)
}

fn ansi_cell(level: u8, accent: HeatmapAccent) -> String {
    match level {
        0 => "\x1b[90m·\x1b[0m ".to_string(),
        1 => format!("\x1b[2;{}m■\x1b[0m ", accent.base_ansi_code()),
        2 => format!("\x1b[{}m■\x1b[0m ", accent.base_ansi_code()),
        3 => format!("\x1b[1;{}m■\x1b[0m ", accent.base_ansi_code()),
        _ => format!("\x1b[1;{}m■\x1b[0m ", accent.bright_ansi_code()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Weekday;

    fn make_entry(day: u8, hours: u64, was_working: bool) -> StatsEntry {
        let date = Date::from_calendar_date(2026, Month::March, day).unwrap();
        let datetime = date.with_hms(9, 0, 0).unwrap().assume_utc();
        let start_time_ms = (datetime.unix_timestamp_nanos() / 1_000_000) as u64;
        StatsEntry {
            start_time_ms,
            end_time_ms: start_time_ms + hours * 3_600 * crate::utils::MILLIS_PER_SECOND,
            duration_ms: hours * 3_600 * crate::utils::MILLIS_PER_SECOND,
            pause_count: 0,
            pause_duration_ms: 0,
            topic: "deep work".to_string(),
            was_working,
        }
    }

    #[test]
    fn aggregates_working_time_by_local_day() {
        let entries = vec![
            make_entry(2, 1, true),
            make_entry(2, 2, true),
            make_entry(2, 3, false),
            make_entry(4, 4, true),
        ];

        let heatmap = build_heatmap(&entries, 2026, UtcOffset::UTC).unwrap();
        let mar_2 = Date::from_calendar_date(2026, Month::March, 2).unwrap();
        let mar_4 = Date::from_calendar_date(2026, Month::March, 4).unwrap();

        let mar_2_cell = heatmap
            .cells
            .iter()
            .find(|cell| cell.date == mar_2)
            .unwrap();
        assert_eq!(
            mar_2_cell.working_ms,
            3 * 3_600 * crate::utils::MILLIS_PER_SECOND
        );

        let mar_4_cell = heatmap
            .cells
            .iter()
            .find(|cell| cell.date == mar_4)
            .unwrap();
        assert_eq!(
            mar_4_cell.working_ms,
            4 * 3_600 * crate::utils::MILLIS_PER_SECOND
        );
        assert_eq!(
            heatmap.max_working_ms,
            4 * 3_600 * crate::utils::MILLIS_PER_SECOND
        );
    }

    #[test]
    fn intensity_is_based_on_working_time() {
        assert_eq!(crate::utils::heatmap_intensity(0, 10), 0);
        assert_eq!(crate::utils::heatmap_intensity(10, 10), 4);
        assert_eq!(crate::utils::heatmap_intensity(1, 16), 1);
        assert_eq!(crate::utils::heatmap_intensity(4, 16), 2);
        assert_eq!(crate::utils::heatmap_intensity(9, 16), 3);
    }

    #[test]
    fn plain_renderer_includes_month_labels_and_legend() {
        let entries = vec![make_entry(1, 2, true), make_entry(10, 5, true)];
        let heatmap = build_heatmap(&entries, 2026, UtcOffset::UTC).unwrap();
        let rendered = render_heatmap(&heatmap, ColorMode::Plain, HeatmapAccent::Green);

        assert!(rendered.contains("Mar"));
        assert!(rendered.contains("Less"));
        assert!(rendered.contains("More"));
    }

    #[test]
    fn year_padding_days_are_blank_and_month_labels_are_unique() {
        let entries = vec![make_entry(2, 1, true)];
        let heatmap = build_heatmap(&entries, 2026, UtcOffset::UTC).unwrap();
        let rendered = render_heatmap(&heatmap, ColorMode::Plain, HeatmapAccent::Green);

        let jan_count = rendered.match_indices("Jan").count();
        assert_eq!(jan_count, 1);

        let padded_dec_31 = Date::from_calendar_date(2025, Month::December, 31).unwrap();
        let blank_cell = render_cell(
            HeatCell {
                date: padded_dec_31,
                in_window: false,
                working_ms: 0,
            },
            heatmap.max_working_ms,
            ColorMode::Plain,
            HeatmapAccent::Green,
        );
        assert_eq!(blank_cell, "  ");
    }

    #[test]
    fn start_of_week_aligns_to_sunday() {
        let date = Date::from_calendar_date(2026, Month::March, 12).unwrap();
        let sunday = sunday_start_of_week(date);
        assert_eq!(sunday.weekday(), Weekday::Sunday);
        assert_eq!(sunday.day(), 8);
    }
}
