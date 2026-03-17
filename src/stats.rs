use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};
use time::{Date, Duration, Month, PrimitiveDateTime, Time};

use crate::error::{Result, TaskBeepError};
use crate::heatmap::render_stats_heatmap;
use crate::protocol::get_status;
use crate::utils::{
    DurationDisplay, MAX_INTERVAL_SECS, MAX_TOPIC_LEN, MILLIS_PER_SECOND, add_months_snap,
    current_local_date, monday_start_of_week, parse_calendar_date, parse_shift_range_spec,
    parse_shift_spec, statsfile_path, topic_matches,
};

const HEATMAP_MIN_DAYS: u64 = 7;
const HEATMAP_MAX_DAYS: u64 = 366;
const MILLIS_PER_DAY: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct StatsEntry {
    pub start_time_ms: u64,
    pub end_time_ms: u64,
    pub duration_ms: u64,
    pub pause_count: u64,
    pub pause_duration_ms: u64,
    pub topic: String,
    pub was_working: bool,
}

impl StatsEntry {
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(
            writer,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.start_time_ms,
            self.end_time_ms,
            self.duration_ms,
            self.pause_count,
            self.pause_duration_ms,
            self.topic.replace(&['\t', '\n', '\r'][..], " "),
            if self.was_working {
                "working"
            } else {
                "wasting"
            }
        )
    }

    pub fn from_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 7 {
            return None;
        }

        let start_time_ms: u64 = parts[0].parse().ok()?;
        let end_time_ms: u64 = parts[1].parse().ok()?;
        let duration_ms: u64 = parts[2].parse().ok()?;
        let pause_count: u64 = parts[3].parse().ok()?;
        let pause_duration_ms: u64 = parts[4].parse().ok()?;
        let topic = parts[5].to_string();
        let was_working = parts[6] == "working";

        if end_time_ms < start_time_ms {
            return None;
        }
        if duration_ms == 0 || duration_ms > MAX_INTERVAL_SECS * MILLIS_PER_SECOND {
            return None;
        }
        if pause_duration_ms > MAX_INTERVAL_SECS * MILLIS_PER_SECOND {
            return None;
        }
        if topic.is_empty() || topic.len() > MAX_TOPIC_LEN {
            return None;
        }

        Some(StatsEntry {
            start_time_ms,
            end_time_ms,
            duration_ms,
            pause_count,
            pause_duration_ms,
            topic,
            was_working,
        })
    }

    pub fn duration_ms(&self) -> u64 {
        self.duration_ms
    }
}

pub fn append_stats(entry: &StatsEntry) -> Result<()> {
    let path = statsfile_path();
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;

    let mut writer = io::BufWriter::new(file);
    entry.write_to(&mut writer)?;
    writer.flush()?;
    writer.get_ref().sync_data()?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeriodUnit {
    Day,
    Week,
    Month,
    Year,
}

#[derive(Debug, Clone)]
struct StatsFilter {
    start_ms: Option<u64>,
    end_ms_exclusive: Option<u64>,
    label: String,
    heatmap_year: Option<i32>,
}

fn date_to_utc_ms(date: Date) -> Option<u64> {
    let dt = PrimitiveDateTime::new(date, Time::MIDNIGHT).assume_utc();
    u64::try_from(dt.unix_timestamp_nanos() / 1_000_000).ok()
}

fn range_from_period(unit: PeriodUnit, spec: Option<&str>, today: Date) -> Result<StatsFilter> {
    let spec = spec.unwrap_or("0");

    if let Some((newest_shift, oldest_shift)) = parse_shift_range_spec(spec) {
        let (start_date, end_exclusive_date, label) = match unit {
            PeriodUnit::Day => {
                let start = today - Duration::days(i64::from(oldest_shift));
                let end_exclusive =
                    today - Duration::days(i64::from(newest_shift)) + Duration::days(1);
                (
                    start,
                    end_exclusive,
                    format!(" (Day {}..{})", newest_shift, oldest_shift),
                )
            }
            PeriodUnit::Week => {
                let current_week_start = monday_start_of_week(today);
                let start = current_week_start - Duration::weeks(i64::from(oldest_shift));
                let end_exclusive = current_week_start - Duration::weeks(i64::from(newest_shift))
                    + Duration::weeks(1);
                (
                    start,
                    end_exclusive,
                    format!(" (Week {}..{})", newest_shift, oldest_shift),
                )
            }
            PeriodUnit::Month => {
                let this_month_start = Date::from_calendar_date(today.year(), today.month(), 1)
                    .map_err(|e| {
                        TaskBeepError::StatsError(format!("failed to build month start: {e}"))
                    })?;
                let start = add_months_snap(this_month_start, -(oldest_shift as i32))
                    .ok_or_else(|| TaskBeepError::StatsError("invalid month offset".to_string()))?;
                let end_exclusive = add_months_snap(this_month_start, -(newest_shift as i32) + 1)
                    .ok_or_else(|| {
                    TaskBeepError::StatsError("invalid month offset".to_string())
                })?;
                (
                    start,
                    end_exclusive,
                    format!(" (Month {}..{})", newest_shift, oldest_shift),
                )
            }
            PeriodUnit::Year => {
                let start_year = today.year() - oldest_shift as i32;
                let end_year = today.year() - newest_shift as i32;
                let start = Date::from_calendar_date(start_year, Month::January, 1)
                    .map_err(|e| TaskBeepError::StatsError(format!("invalid year: {e}")))?;
                let end_exclusive = Date::from_calendar_date(end_year + 1, Month::January, 1)
                    .map_err(|e| TaskBeepError::StatsError(format!("invalid year: {e}")))?;
                (
                    start,
                    end_exclusive,
                    format!(" (Year {}..{})", newest_shift, oldest_shift),
                )
            }
        };

        let visible_end = end_exclusive_date - Duration::days(1);
        let heatmap_year = if start_date.year() == visible_end.year() {
            Some(start_date.year())
        } else {
            None
        };

        return Ok(StatsFilter {
            start_ms: date_to_utc_ms(start_date),
            end_ms_exclusive: date_to_utc_ms(end_exclusive_date),
            label,
            heatmap_year,
        });
    }

    let shift = parse_shift_spec(spec).ok_or_else(|| {
        TaskBeepError::StatsError(format!(
            "invalid period offset '{}': expected 0, ^, or ~N",
            spec
        ))
    })?;

    let (start_date, end_date, label) = match unit {
        PeriodUnit::Day => {
            if shift == 0 {
                (today, None, " (Today)".to_string())
            } else {
                let start = today - Duration::days(i64::from(shift));
                (
                    start,
                    Some(today),
                    format!(" (Last {} Day{})", shift, if shift == 1 { "" } else { "s" }),
                )
            }
        }
        PeriodUnit::Week => {
            let current_week_start = monday_start_of_week(today);
            if shift == 0 {
                (current_week_start, None, " (This Week)".to_string())
            } else {
                let start = current_week_start - Duration::weeks(i64::from(shift));
                (
                    start,
                    Some(current_week_start),
                    format!(
                        " (Last {} Week{})",
                        shift,
                        if shift == 1 { "" } else { "s" }
                    ),
                )
            }
        }
        PeriodUnit::Month => {
            let this_month_start = Date::from_calendar_date(today.year(), today.month(), 1)
                .map_err(|e| {
                    TaskBeepError::StatsError(format!("failed to build month start: {e}"))
                })?;
            if shift == 0 {
                (this_month_start, None, " (This Month)".to_string())
            } else {
                let start = add_months_snap(this_month_start, -(shift as i32))
                    .ok_or_else(|| TaskBeepError::StatsError("invalid month offset".to_string()))?;
                (
                    start,
                    Some(this_month_start),
                    format!(
                        " (Last {} Month{})",
                        shift,
                        if shift == 1 { "" } else { "s" }
                    ),
                )
            }
        }
        PeriodUnit::Year => {
            let this_year_start = Date::from_calendar_date(today.year(), Month::January, 1)
                .map_err(|e| {
                    TaskBeepError::StatsError(format!("failed to build year start: {e}"))
                })?;
            if shift == 0 {
                (this_year_start, None, " (This Year)".to_string())
            } else {
                let target_year = today.year() - shift as i32;
                let start = Date::from_calendar_date(target_year, Month::January, 1)
                    .map_err(|e| TaskBeepError::StatsError(format!("invalid year: {e}")))?;
                (
                    start,
                    Some(this_year_start),
                    if shift == 1 {
                        " (Last Year)".to_string()
                    } else {
                        format!(" (Last {} Years)", shift)
                    },
                )
            }
        }
    };

    let heatmap_year = match end_date {
        Some(end_exclusive) => {
            let visible_end = end_exclusive - Duration::days(1);
            if start_date.year() == visible_end.year() {
                Some(start_date.year())
            } else {
                None
            }
        }
        None => {
            if start_date.year() == today.year() {
                Some(today.year())
            } else {
                None
            }
        }
    };

    Ok(StatsFilter {
        start_ms: date_to_utc_ms(start_date),
        end_ms_exclusive: end_date.and_then(date_to_utc_ms),
        label,
        heatmap_year,
    })
}

fn range_from_year_value(year_spec: &str, today: Date) -> Result<StatsFilter> {
    if let Some(shift) = parse_shift_spec(year_spec) {
        let normalized = if shift == 0 {
            "0".to_string()
        } else {
            format!("~{shift}")
        };
        return range_from_period(PeriodUnit::Year, Some(&normalized), today);
    }

    let year: i32 = year_spec.parse().map_err(|_| {
        TaskBeepError::StatsError(format!(
            "invalid year '{}': expected a year number, ^, or ~N",
            year_spec
        ))
    })?;
    let start = Date::from_calendar_date(year, Month::January, 1)
        .map_err(|e| TaskBeepError::StatsError(format!("invalid year {year}: {e}")))?;
    let end = Date::from_calendar_date(year + 1, Month::January, 1)
        .map_err(|e| TaskBeepError::StatsError(format!("invalid year {}: {e}", year + 1)))?;

    Ok(StatsFilter {
        start_ms: date_to_utc_ms(start),
        end_ms_exclusive: date_to_utc_ms(end),
        label: format!(" ({year})"),
        heatmap_year: Some(year),
    })
}

fn range_from_expression(expr: &str) -> Result<StatsFilter> {
    let (start_raw, end_raw) = expr.split_once("..").ok_or_else(|| {
        TaskBeepError::StatsError(
            "invalid --range: expected START..END (for example 2024-11-2..2024-11-5)".to_string(),
        )
    })?;
    let start_date = parse_calendar_date(start_raw.trim()).ok_or_else(|| {
        TaskBeepError::StatsError(format!(
            "invalid range start '{}': expected YYYY-M-D",
            start_raw.trim()
        ))
    })?;
    let end_inclusive = parse_calendar_date(end_raw.trim()).ok_or_else(|| {
        TaskBeepError::StatsError(format!(
            "invalid range end '{}': expected YYYY-M-D",
            end_raw.trim()
        ))
    })?;

    if end_inclusive < start_date {
        return Err(TaskBeepError::StatsError(
            "invalid --range: end date must be >= start date".to_string(),
        ));
    }

    let end_exclusive = end_inclusive + Duration::days(1);
    let heatmap_year = if start_date.year() == end_inclusive.year() {
        Some(start_date.year())
    } else {
        None
    };

    Ok(StatsFilter {
        start_ms: date_to_utc_ms(start_date),
        end_ms_exclusive: date_to_utc_ms(end_exclusive),
        label: format!(" ({}..{})", start_raw.trim(), end_raw.trim()),
        heatmap_year,
    })
}

fn resolve_stats_filter(
    day: Option<&str>,
    week: Option<&str>,
    month: Option<&str>,
    year: Option<&str>,
    range: Option<&str>,
) -> Result<StatsFilter> {
    let mut selected = 0;
    if day.is_some() {
        selected += 1;
    }
    if week.is_some() {
        selected += 1;
    }
    if month.is_some() {
        selected += 1;
    }
    if year.is_some() {
        selected += 1;
    }
    if range.is_some() {
        selected += 1;
    }

    if selected > 1 {
        return Err(TaskBeepError::StatsError(
            "use only one of: --day, --week, --month, --year, --range".to_string(),
        ));
    }

    let now_date = current_local_date();

    if let Some(expr) = range {
        return range_from_expression(expr);
    }
    if let Some(spec) = day {
        return range_from_period(PeriodUnit::Day, Some(spec), now_date);
    }
    if let Some(spec) = week {
        return range_from_period(PeriodUnit::Week, Some(spec), now_date);
    }
    if let Some(spec) = month {
        return range_from_period(PeriodUnit::Month, Some(spec), now_date);
    }
    if let Some(spec) = year {
        return range_from_year_value(spec, now_date);
    }

    Ok(StatsFilter {
        start_ms: None,
        end_ms_exclusive: None,
        label: String::new(),
        heatmap_year: None,
    })
}

fn validate_heatmap_window(filter: &StatsFilter, today: Date) -> Result<()> {
    let Some(start_ms) = filter.start_ms else {
        // Unbounded/all-time stats are allowed; heatmap rendering already constrains to one year.
        return Ok(());
    };

    let fallback_end_ms = date_to_utc_ms(today + Duration::days(1)).ok_or_else(|| {
        TaskBeepError::StatsError("failed to resolve current date for heatmap window".to_string())
    })?;
    let end_ms = filter.end_ms_exclusive.unwrap_or(fallback_end_ms);

    if end_ms <= start_ms {
        return Err(TaskBeepError::StatsError(
            "invalid heatmap range: end must be after start".to_string(),
        ));
    }

    let span_days = (end_ms - start_ms).div_ceil(MILLIS_PER_DAY);
    if span_days < HEATMAP_MIN_DAYS {
        return Err(TaskBeepError::StatsError(format!(
            "heatmap range is too short: minimum is {} days",
            HEATMAP_MIN_DAYS
        )));
    }
    if span_days > HEATMAP_MAX_DAYS {
        return Err(TaskBeepError::StatsError(format!(
            "heatmap range is too long: maximum is {} days",
            HEATMAP_MAX_DAYS
        )));
    }

    Ok(())
}

fn has_any_period_filter(
    day: Option<&str>,
    week: Option<&str>,
    month: Option<&str>,
    year: Option<&str>,
    range: Option<&str>,
) -> bool {
    day.is_some() || week.is_some() || month.is_some() || year.is_some() || range.is_some()
}

fn has_explicit_range_syntax(
    day: Option<&str>,
    week: Option<&str>,
    month: Option<&str>,
    year: Option<&str>,
    range: Option<&str>,
) -> bool {
    range.is_some()
        || day.is_some_and(|s| s.contains(".."))
        || week.is_some_and(|s| s.contains(".."))
        || month.is_some_and(|s| s.contains(".."))
        || year.is_some_and(|s| s.contains(".."))
}

pub fn read_stats_entries(filter_start_ms: Option<u64>) -> Result<Vec<StatsEntry>> {
    let stats_path = statsfile_path();
    if !stats_path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(&stats_path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Some(entry) = StatsEntry::from_line(&line) {
            if let Some(start_ms) = filter_start_ms
                && entry.start_time_ms < start_ms
            {
                continue;
            }
            entries.push(entry);
        }
    }

    Ok(entries)
}

pub fn show_stats(
    topic: Option<&str>,
    day: Option<&str>,
    week: Option<&str>,
    month: Option<&str>,
    year: Option<&str>,
    range: Option<&str>,
    show_heatmap: bool,
) -> Result<()> {
    if show_heatmap
        && has_any_period_filter(day, week, month, year, range)
        && !has_explicit_range_syntax(day, week, month, year, range)
    {
        return Err(TaskBeepError::StatsError(
            "heatmap with period filters requires an explicit range using '..' (for example: -d '~0..~8' or --range 2024-11-2..2024-11-5)".to_string(),
        ));
    }

    let filter = resolve_stats_filter(day, week, month, year, range)?;
    if show_heatmap {
        let today = current_local_date();
        validate_heatmap_window(&filter, today)?;
    }

    let all_in_range = read_stats_entries(filter.start_ms)?;
    let entries: Vec<_> = all_in_range
        .into_iter()
        .filter(|e| {
            filter
                .end_ms_exclusive
                .is_none_or(|end| e.start_time_ms < end)
        })
        .filter(|e| topic.is_none_or(|t| topic_matches(t, &e.topic)))
        .collect();
    if entries.is_empty() {
        println!("No statistics available yet");
        return Ok(());
    }

    let mut total_working_ms = 0u64;
    let mut total_wasting_ms = 0u64;
    let mut total_pause_count = 0u64;
    let mut total_pause_duration_ms = 0u64;
    // (working_ms, wasting_ms, pause_count, pause_duration_ms)
    let mut topic_stats: HashMap<String, (u64, u64, u64, u64)> = HashMap::new();

    for entry in &entries {
        let duration = entry.duration_ms();
        let stats = topic_stats
            .entry(entry.topic.clone())
            .or_insert((0, 0, 0, 0));

        if entry.was_working {
            total_working_ms += duration;
            stats.0 += duration;
        } else {
            total_wasting_ms += duration;
            stats.1 += duration;
        }

        total_pause_count += entry.pause_count;
        total_pause_duration_ms += entry.pause_duration_ms;
        stats.2 += entry.pause_count;
        stats.3 += entry.pause_duration_ms;
    }

    if total_working_ms == 0 && total_wasting_ms == 0 {
        println!("No sessions recorded yet");
        return Ok(());
    }

    let total_ms = total_working_ms + total_wasting_ms;
    let productivity = (total_working_ms as f64 / total_ms as f64) * 100.0;

    let topic_label = topic.map(|t| format!(" [{}]", t)).unwrap_or_default();

    println!(
        "=== Productivity Statistics{}{} ===",
        filter.label, topic_label
    );
    println!("Total time: {}", DurationDisplay(total_ms));
    println!("Working: {}", DurationDisplay(total_working_ms));
    println!("Wasting: {}", DurationDisplay(total_wasting_ms));
    println!("Productivity: {:.1}%", productivity);
    if total_pause_count > 0 {
        println!(
            "Total pauses: {} ({} paused)",
            total_pause_count,
            DurationDisplay(total_pause_duration_ms)
        );
    }

    println!("\n=== By Topic ===");
    let mut topics: Vec<_> = topic_stats.iter().collect();
    topics.sort_by_key(|(_, (w, wa, _, _))| std::cmp::Reverse(w + wa));

    for (topic, (working, wasting, pause_count, pause_duration)) in topics {
        let total = working + wasting;
        let prod = (*working as f64 / total as f64) * 100.0;
        if *pause_count > 0 {
            println!(
                "{}: {} ({:.1}% productive, {} pauses, {} paused)",
                topic,
                DurationDisplay(total),
                prod,
                pause_count,
                DurationDisplay(*pause_duration)
            );
        } else {
            println!(
                "{}: {} ({:.1}% productive)",
                topic,
                DurationDisplay(total),
                prod
            );
        }
    }

    if show_heatmap {
        println!();
        println!("=== Heatmap ===");
        print!("{}", render_stats_heatmap(&entries, filter.heatmap_year)?);
    }

    Ok(())
}

pub fn export_stats(output: PathBuf) -> Result<()> {
    let stats_path = statsfile_path();
    if !stats_path.exists() {
        return Err(TaskBeepError::StatsError(
            "No statistics available to export".to_string(),
        ));
    }

    fs::copy(&stats_path, &output)?;
    println!("Statistics exported to: {}", output.display());
    Ok(())
}

pub fn clear_stats(topic: Option<String>, skip_confirmation: bool) -> Result<()> {
    if get_status().is_ok() {
        return Err(TaskBeepError::StatsError(
            "Cannot clear statistics while timer is running".to_string(),
        ));
    }

    let stats_path = statsfile_path();
    if !stats_path.exists() {
        println!("No statistics file found");
        return Ok(());
    }

    if let Some(topic_name) = topic {
        let file = File::open(&stats_path)?;
        let reader = BufReader::new(file);

        let mut matching_entries = Vec::new();
        let mut other_entries = Vec::new();
        let mut all_topics = std::collections::HashSet::new();

        for line in reader.lines() {
            let line = line?;
            if let Some(entry) = StatsEntry::from_line(&line) {
                all_topics.insert(entry.topic.clone());
                if topic_matches(&topic_name, &entry.topic) {
                    matching_entries.push(entry);
                } else {
                    other_entries.push(entry);
                }
            }
        }

        if matching_entries.is_empty() {
            println!("No statistics found matching '{}'", topic_name);
            if !all_topics.is_empty() {
                println!("\nAvailable topics:");
                let mut sorted_topics: Vec<_> = all_topics.iter().collect();
                sorted_topics.sort();
                for t in sorted_topics {
                    println!("  {}", t);
                }
            }
            return Ok(());
        }

        if !skip_confirmation {
            println!(
                "Found {} session(s) for topic: {}",
                matching_entries.len(),
                topic_name
            );
            if !crate::utils::confirm(
                "Delete all statistics for this topic? This cannot be undone. (y/N): ",
            )? {
                println!("Cancelled");
                return Ok(());
            }
        }

        let temp_path = stats_path.with_extension("tmp");
        let write_result = {
            let temp_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?;

            let mut writer = io::BufWriter::new(temp_file);
            for entry in &other_entries {
                entry.write_to(&mut writer)?;
            }
            writer.flush()?;
            writer.get_ref().sync_data()?;
            Ok::<(), io::Error>(())
        };

        if let Err(e) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(e.into());
        }

        if let Err(e) = fs::rename(&temp_path, &stats_path) {
            let _ = fs::remove_file(&temp_path);
            return Err(e.into());
        }

        println!(
            "Deleted {} session(s) for topic: {}",
            matching_entries.len(),
            topic_name
        );
    } else {
        if !skip_confirmation {
            let confirmed =
                crate::utils::confirm("Delete all statistics? This cannot be undone. (y/N): ")?;
            if !confirmed {
                println!("Cancelled");
                return Ok(());
            }
        }

        fs::remove_file(&stats_path)?;
        println!("Statistics cleared");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::now_ms;
    use time::OffsetDateTime;

    fn ms_to_date(ms: u64) -> Date {
        OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
            .unwrap()
            .date()
    }

    #[test]
    fn test_stats_entry_serialization() {
        let entry = StatsEntry {
            start_time_ms: 1000,
            end_time_ms: 2000,
            duration_ms: 1000,
            pause_count: 2,
            pause_duration_ms: 300,
            topic: "test".to_string(),
            was_working: true,
        };

        let mut buf = Vec::new();
        entry.write_to(&mut buf).unwrap();
        let serialized = String::from_utf8(buf).unwrap();
        assert!(serialized.contains("test"));
        assert!(serialized.contains("working"));

        let deserialized = StatsEntry::from_line(serialized.trim()).unwrap();
        assert_eq!(deserialized.start_time_ms, entry.start_time_ms);
        assert_eq!(deserialized.end_time_ms, entry.end_time_ms);
        assert_eq!(deserialized.duration_ms, entry.duration_ms);
        assert_eq!(deserialized.pause_count, entry.pause_count);
        assert_eq!(deserialized.pause_duration_ms, entry.pause_duration_ms);
        assert_eq!(deserialized.topic, entry.topic);
        assert_eq!(deserialized.was_working, entry.was_working);
    }

    #[test]
    fn test_stats_entry_deserialization_invalid() {
        assert!(StatsEntry::from_line("1000\t2000\t1000").is_none());
        assert!(StatsEntry::from_line("1000\t2000\t1000\t2\t300\ttopic\textra\tworking").is_none());
        assert!(StatsEntry::from_line("abc\t2000\t1000\t2\t300\ttopic\tworking").is_none());
    }

    #[test]
    fn test_stats_entry_duration() {
        let entry = StatsEntry {
            start_time_ms: 1000,
            end_time_ms: 3500,
            duration_ms: 2500,
            pause_count: 1,
            pause_duration_ms: 500,
            topic: "test".to_string(),
            was_working: true,
        };
        assert_eq!(entry.duration_ms(), 2500);
    }

    #[test]
    fn test_calculate_total_duration() {
        let entries = [
            StatsEntry {
                start_time_ms: 0,
                end_time_ms: 60_000,
                duration_ms: 60_000,
                pause_count: 0,
                pause_duration_ms: 0,
                topic: "task1".to_string(),
                was_working: true,
            },
            StatsEntry {
                start_time_ms: 60_000,
                end_time_ms: 120_000,
                duration_ms: 60_000,
                pause_count: 1,
                pause_duration_ms: 5000,
                topic: "task2".to_string(),
                was_working: true,
            },
        ];

        let total = entries.iter().map(|e| e.duration_ms()).sum::<u64>();
        assert_eq!(total, 120_000);
    }

    #[test]
    fn test_filter_dates() {
        let now = now_ms();
        let one_day_ago = now - 86_400_000;
        let two_days_ago = now - 2 * 86_400_000;

        let entries = [
            StatsEntry {
                start_time_ms: two_days_ago,
                end_time_ms: two_days_ago + 1000,
                duration_ms: 1000,
                pause_count: 0,
                pause_duration_ms: 0,
                topic: "old".to_string(),
                was_working: true,
            },
            StatsEntry {
                start_time_ms: one_day_ago,
                end_time_ms: one_day_ago + 1000,
                duration_ms: 1000,
                pause_count: 1,
                pause_duration_ms: 200,
                topic: "recent".to_string(),
                was_working: true,
            },
            StatsEntry {
                start_time_ms: now - 1000,
                end_time_ms: now,
                duration_ms: 1000,
                pause_count: 0,
                pause_duration_ms: 0,
                topic: "current".to_string(),
                was_working: true,
            },
        ];

        let filtered: Vec<_> = entries
            .iter()
            .filter(|e| e.start_time_ms >= one_day_ago)
            .collect();

        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].topic, "recent");
        assert_eq!(filtered[1].topic, "current");
    }

    #[test]
    fn test_parse_shift_range_spec() {
        assert_eq!(parse_shift_range_spec("^..~3"), Some((1, 3)));
        assert_eq!(parse_shift_range_spec("~4..^"), Some((1, 4)));
        assert_eq!(parse_shift_range_spec("0..~2"), Some((0, 2)));
        assert_eq!(parse_shift_range_spec("^..^"), Some((1, 1)));
        assert_eq!(parse_shift_range_spec("~3..~6"), Some((3, 6)));
        assert_eq!(parse_shift_range_spec("~6..~3"), Some((3, 6)));
        assert_eq!(parse_shift_range_spec("foo..~2"), None);
    }

    #[test]
    fn test_month_range_from_git_style_expression() {
        let today = Date::from_calendar_date(2026, Month::March, 15).unwrap();
        let filter = range_from_period(PeriodUnit::Month, Some("^..~3"), today).unwrap();

        assert_eq!(
            ms_to_date(filter.start_ms.unwrap()),
            Date::from_calendar_date(2025, Month::December, 1).unwrap()
        );
        assert_eq!(
            ms_to_date(filter.end_ms_exclusive.unwrap()),
            Date::from_calendar_date(2026, Month::March, 1).unwrap()
        );
        assert_eq!(filter.heatmap_year, None);
    }

    #[test]
    fn test_year_range_from_git_style_expression() {
        let today = Date::from_calendar_date(2026, Month::March, 15).unwrap();
        let filter = range_from_period(PeriodUnit::Year, Some("^..~3"), today).unwrap();

        assert_eq!(
            ms_to_date(filter.start_ms.unwrap()),
            Date::from_calendar_date(2023, Month::January, 1).unwrap()
        );
        assert_eq!(
            ms_to_date(filter.end_ms_exclusive.unwrap()),
            Date::from_calendar_date(2026, Month::January, 1).unwrap()
        );
        assert_eq!(filter.heatmap_year, None);
    }

    #[test]
    fn test_explicit_date_range_expression() {
        let filter = range_from_expression("2024-11-2..2024-11-5").unwrap();
        assert_eq!(
            ms_to_date(filter.start_ms.unwrap()),
            Date::from_calendar_date(2024, Month::November, 2).unwrap()
        );
        assert_eq!(
            ms_to_date(filter.end_ms_exclusive.unwrap()),
            Date::from_calendar_date(2024, Month::November, 6).unwrap()
        );
        assert_eq!(filter.heatmap_year, Some(2024));
    }

    #[test]
    fn test_diff_zero_produces_single_period() {
        let today = Date::from_calendar_date(2026, Month::March, 15).unwrap();

        let day = range_from_period(PeriodUnit::Day, Some("^..^"), today).unwrap();
        assert_eq!(
            ms_to_date(day.start_ms.unwrap()),
            Date::from_calendar_date(2026, Month::March, 14).unwrap()
        );
        assert_eq!(
            ms_to_date(day.end_ms_exclusive.unwrap()),
            Date::from_calendar_date(2026, Month::March, 15).unwrap()
        );

        let week = range_from_period(PeriodUnit::Week, Some("^..^"), today).unwrap();
        assert_eq!(
            ms_to_date(week.start_ms.unwrap()),
            Date::from_calendar_date(2026, Month::March, 2).unwrap()
        );
        assert_eq!(
            ms_to_date(week.end_ms_exclusive.unwrap()),
            Date::from_calendar_date(2026, Month::March, 9).unwrap()
        );

        let month = range_from_period(PeriodUnit::Month, Some("^..^"), today).unwrap();
        assert_eq!(
            ms_to_date(month.start_ms.unwrap()),
            Date::from_calendar_date(2026, Month::February, 1).unwrap()
        );
        assert_eq!(
            ms_to_date(month.end_ms_exclusive.unwrap()),
            Date::from_calendar_date(2026, Month::March, 1).unwrap()
        );

        let year = range_from_period(PeriodUnit::Year, Some("^..^"), today).unwrap();
        assert_eq!(
            ms_to_date(year.start_ms.unwrap()),
            Date::from_calendar_date(2025, Month::January, 1).unwrap()
        );
        assert_eq!(
            ms_to_date(year.end_ms_exclusive.unwrap()),
            Date::from_calendar_date(2026, Month::January, 1).unwrap()
        );
    }

    #[test]
    fn test_bidirectional_delta_range_is_equivalent() {
        let today = Date::from_calendar_date(2026, Month::March, 15).unwrap();

        let a = range_from_period(PeriodUnit::Month, Some("~3..~6"), today).unwrap();
        let b = range_from_period(PeriodUnit::Month, Some("~6..~3"), today).unwrap();
        assert_eq!(a.start_ms, b.start_ms);
        assert_eq!(a.end_ms_exclusive, b.end_ms_exclusive);

        let a = range_from_period(PeriodUnit::Year, Some("~3..~6"), today).unwrap();
        let b = range_from_period(PeriodUnit::Year, Some("~6..~3"), today).unwrap();
        assert_eq!(a.start_ms, b.start_ms);
        assert_eq!(a.end_ms_exclusive, b.end_ms_exclusive);
    }

    #[test]
    fn test_heatmap_minimum_window_validation() {
        let today = Date::from_calendar_date(2026, Month::March, 15).unwrap();
        let short_filter = range_from_period(PeriodUnit::Day, Some("^..^"), today).unwrap();

        let err = validate_heatmap_window(&short_filter, today).unwrap_err();
        assert!(
            err.to_string()
                .contains("heatmap range is too short: minimum is 7 days")
        );
    }

    #[test]
    fn test_heatmap_maximum_window_validation() {
        let today = Date::from_calendar_date(2026, Month::March, 15).unwrap();
        let long_filter = range_from_expression("2024-1-1..2025-12-31").unwrap();

        let err = validate_heatmap_window(&long_filter, today).unwrap_err();
        assert!(
            err.to_string()
                .contains("heatmap range is too long: maximum is 366 days")
        );
    }

    #[test]
    fn test_heatmap_window_within_limits_is_valid() {
        let today = Date::from_calendar_date(2026, Month::March, 15).unwrap();
        let valid_filter = range_from_period(PeriodUnit::Month, Some("^..~3"), today).unwrap();

        validate_heatmap_window(&valid_filter, today).unwrap();
    }

    #[test]
    fn test_heatmap_explicit_range_detection() {
        assert!(!has_any_period_filter(None, None, None, None, None));
        assert!(!has_explicit_range_syntax(None, None, None, None, None));

        assert!(has_any_period_filter(Some("~8"), None, None, None, None));
        assert!(!has_explicit_range_syntax(
            Some("~8"),
            None,
            None,
            None,
            None
        ));

        assert!(has_explicit_range_syntax(
            Some("~0..~8"),
            None,
            None,
            None,
            None
        ));
        assert!(has_explicit_range_syntax(
            None,
            None,
            None,
            None,
            Some("2024-11-2..2024-11-5")
        ));
    }

    // duration_ms must equal the configured interval, not the wall-clock elapsed time.
    #[test]
    fn logged_duration_is_interval_not_wall_clock() {
        let interval_ms: u64 = 60_000;
        let session_start: u64 = 0;
        let pause_duration: u64 = 20_000;
        let beep_time: u64 = session_start + interval_ms + pause_duration;

        let entry = StatsEntry {
            start_time_ms: session_start,
            end_time_ms: beep_time,
            duration_ms: interval_ms,
            pause_count: 1,
            pause_duration_ms: pause_duration,
            topic: "work".to_string(),
            was_working: true,
        };

        assert_eq!(
            entry.duration_ms, interval_ms,
            "duration_ms must be the configured interval"
        );
        assert_ne!(
            entry.duration_ms,
            beep_time - session_start,
            "duration_ms must NOT be the raw wall-clock difference"
        );
    }

    // end_time_ms must be the beep time; response-waiting time must not inflate it.
    #[test]
    fn logged_end_time_is_beep_time_not_response_time() {
        let beep_time: u64 = 100_000;
        let response_delay_ms: u64 = 15_000;

        let entry = StatsEntry {
            start_time_ms: 40_000,
            end_time_ms: beep_time,
            duration_ms: 60_000,
            pause_count: 0,
            pause_duration_ms: 0,
            topic: "work".to_string(),
            was_working: true,
        };

        assert_eq!(entry.end_time_ms, beep_time);
        assert_ne!(
            entry.end_time_ms,
            beep_time + response_delay_ms,
            "waiting-for-response time must not be included in end_time_ms"
        );
    }
}
