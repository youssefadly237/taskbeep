use std::{collections::HashMap, process::Command, time::Duration};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    DefaultTerminal,
    style::{Color, Modifier, Style},
    text::{Line, Span},
};
use time::{Date, Duration as TimeDuration, Month, OffsetDateTime, UtcOffset};

use crate::{
    commands::{pause_resume_toggle_quiet, stop_timer},
    error::{Result, TaskBeepError},
    get_config,
    heatmap::{HeatCell, HeatDayStats, build_heat_aggregation},
    protocol::{CMD_TOGGLE, Status, StatusResponse, get_status},
    stats::{StatsEntry, read_stats_entries},
    utils::{
        DurationDisplay, HeatmapAccent, MAX_INTERVAL_SECS, day_label, heatmap_cell_level,
        heatmap_legend_levels, month_abbrev, now_ms, parse_calendar_date, shift_months_with_day,
        topic_matches, validate_interval, weekday_abbrev,
    },
};

const STREAKS_PANEL_HEIGHT: u16 = 10;
const HEATMAP_PANEL_HEIGHT: u16 = 12;

mod ascii;
#[cfg(test)]
mod layout_tests;
mod render;

use self::ascii::{TIMER_FONT_HEIGHT, timer_font_glyph};

#[derive(Debug, Clone)]
enum UiMode {
    Normal,
    FilterInput {
        value: String,
    },
    StartInput {
        value: String,
    },
    RangeInput {
        start: String,
        end: String,
        editing_end: bool,
    },
    StopConfirm,
}

type DayStats = HeatDayStats;

#[derive(Debug, Clone)]
struct StreakInfo {
    days: u32,
    start: Date,
    end: Date,
}

#[derive(Debug, Clone)]
struct HeatmapModel {
    title: String,
    weeks: usize,
    max_working_ms: u64,
    cells: Vec<HeatCell>,
    day_stats: HashMap<Date, DayStats>,
    topics_best_streak: HashMap<String, StreakInfo>,
    overall_best_streak: Option<StreakInfo>,
}

#[derive(Debug, Clone)]
struct RangeFilter {
    start_date: Date,
    end_date: Date,
    start_input: String,
    end_input: String,
}

#[derive(Debug, Clone)]
struct TimerBanner {
    state_line: String,
}

#[derive(Debug, Clone, Copy)]
enum NoticeKind {
    Info,
    Error,
}

#[derive(Debug, Clone)]
struct FooterNotice {
    kind: NoticeKind,
    message: String,
}

const INTERVAL_STEP_SECS: u64 = 30;
const INTERVAL_MIN_SECS: u64 = 30;

pub fn run_ui() -> Result<()> {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let now = OffsetDateTime::now_utc().to_offset(offset).date();
    let year = now.year();
    let mut app = App::load(year, offset)?;

    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, &mut app);
    ratatui::restore();

    result
}

fn run_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|frame| render::draw(frame, app))?;

        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match app.handle_key(key.code) {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => app.set_error(error.to_string()),
            }
        }

        app.tick();
    }

    Ok(())
}

struct App {
    offset: UtcOffset,
    default_year: i32,
    all_entries: Vec<StatsEntry>,
    model: HeatmapModel,
    selected_index: usize,
    timer: TimerBanner,
    mode: UiMode,
    topic_filter: Option<String>,
    range_filter: Option<RangeFilter>,
    pending_interval_secs: u64,
    last_status: Option<StatusResponse>,
    footer_notice: Option<FooterNotice>,
    next_status_refresh_ms: u64,
    accent: HeatmapAccent,
}

struct WorkWasteChartData {
    work_points: Vec<(f64, f64)>,
    waste_points: Vec<(f64, f64)>,
    x_bounds: [f64; 2],
    y_bounds: [f64; 2],
    x_labels: Vec<Line<'static>>,
    y_labels: Vec<Line<'static>>,
}

impl App {
    fn load(year: i32, offset: UtcOffset) -> Result<Self> {
        let entries = read_stats_entries(None)?;
        let (start, end, title) = year_window(year)?;
        let model = build_heatmap_model(&entries, start, end, title, offset)?;
        let today = OffsetDateTime::now_utc().to_offset(offset).date();
        let selected_index = model
            .cells
            .iter()
            .position(|c| c.date == today)
            .or_else(|| model.cells.iter().position(|c| c.in_window))
            .unwrap_or_default();

        Ok(Self {
            offset,
            default_year: year,
            all_entries: entries,
            model,
            selected_index,
            timer: TimerBanner {
                state_line: "State: loading".to_string(),
            },
            mode: UiMode::Normal,
            topic_filter: None,
            range_filter: None,
            pending_interval_secs: get_config()
                .session_duration
                .clamp(INTERVAL_MIN_SECS, MAX_INTERVAL_SECS),
            last_status: None,
            footer_notice: None,
            next_status_refresh_ms: 0,
            accent: HeatmapAccent::from_env(),
        })
    }

    fn reload(&mut self) -> Result<()> {
        self.all_entries = read_stats_entries(None)?;
        self.rebuild_model()
    }

    fn rebuild_model(&mut self) -> Result<()> {
        let selected_date = self.selected_date();
        let (window_start, window_end, title) = self.active_window()?;
        let filtered_entries: Vec<_> = self
            .all_entries
            .iter()
            .filter(|e| {
                self.topic_filter
                    .as_deref()
                    .is_none_or(|pat| topic_matches(pat, &e.topic))
            })
            .cloned()
            .collect();
        self.model = build_heatmap_model(
            &filtered_entries,
            window_start,
            window_end,
            title,
            self.offset,
        )?;
        self.selected_index = self
            .model
            .cells
            .iter()
            .position(|c| c.date == selected_date)
            .or_else(|| self.model.cells.iter().position(|c| c.in_window))
            .unwrap_or_default();
        Ok(())
    }

    fn active_window(&self) -> Result<(Date, Date, String)> {
        if let Some(range) = &self.range_filter {
            Ok((
                range.start_date,
                range.end_date,
                format!("Heatmap ({}..{})", range.start_date, range.end_date),
            ))
        } else {
            year_window(self.default_year)
        }
    }

    fn tick(&mut self) {
        let now = now_ms();
        if now < self.next_status_refresh_ms {
            return;
        }
        self.next_status_refresh_ms = now + 500;
        let (state_line, status) = build_timer_banner();
        self.last_status = status;
        self.timer = TimerBanner { state_line };
    }

    fn handle_key(&mut self, code: KeyCode) -> Result<bool> {
        let mode = std::mem::replace(&mut self.mode, UiMode::Normal);
        match mode {
            UiMode::Normal => self.handle_normal_key(code),
            UiMode::FilterInput { mut value } => {
                if self.handle_text_input_key(code, &mut value, true)? {
                    self.mode = UiMode::FilterInput { value };
                }
                Ok(false)
            }
            UiMode::StartInput { mut value } => {
                if self.handle_text_input_key(code, &mut value, false)? {
                    self.mode = UiMode::StartInput { value };
                }
                Ok(false)
            }
            UiMode::RangeInput {
                mut start,
                mut end,
                mut editing_end,
            } => {
                if self.handle_range_input_key(code, &mut start, &mut end, &mut editing_end)? {
                    self.mode = UiMode::RangeInput {
                        start,
                        end,
                        editing_end,
                    };
                }
                Ok(false)
            }
            UiMode::StopConfirm => {
                self.mode = UiMode::StopConfirm;
                self.handle_stop_confirm_key(code)
            }
        }
    }

    fn handle_normal_key(&mut self, code: KeyCode) -> Result<bool> {
        match code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Esc => return Ok(true),
            KeyCode::Left | KeyCode::Char('h') => self.move_horizontal(-1),
            KeyCode::Right => self.move_horizontal(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_vertical(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_vertical(1),
            KeyCode::Char('l') => {
                self.clear_error();
                if let Err(error) = self.reload() {
                    self.set_error(format!("reload failed: {error}"));
                } else {
                    self.set_info("reloaded".to_string());
                }
            }
            KeyCode::Char('f') => {
                self.mode = UiMode::FilterInput {
                    value: self.topic_filter.clone().unwrap_or_default(),
                };
            }
            KeyCode::Char('r') | KeyCode::Char('g') => {
                let (start, end) = if let Some(range) = &self.range_filter {
                    (range.start_input.clone(), range.end_input.clone())
                } else {
                    ("~d30".to_string(), "~d0".to_string())
                };
                self.mode = UiMode::RangeInput {
                    start,
                    end,
                    editing_end: false,
                };
            }
            KeyCode::Char('d') => {
                if self.topic_filter.is_some() {
                    self.clear_error();
                    if let Err(error) = self.apply_filter(String::new()) {
                        self.set_error(format!("clear topic filter failed: {error}"));
                    } else {
                        self.set_info("topic filter cleared".to_string());
                    }
                }
            }
            KeyCode::Char('c') => {
                if self.range_filter.is_some() {
                    self.clear_error();
                    if let Err(error) = self.clear_range_filter() {
                        self.set_error(format!("clear range failed: {error}"));
                    } else {
                        self.set_info("range cleared".to_string());
                    }
                }
            }
            KeyCode::Char('s') => {
                self.clear_error();
                self.mode = UiMode::StartInput {
                    value: String::new(),
                };
            }
            KeyCode::Char('t') => {
                self.clear_error();
                match self.toggle_timer() {
                    Ok(message) => self.set_info(message),
                    Err(error) => {
                        self.set_error(format!("toggle failed: {error}"));
                    }
                }
            }
            KeyCode::Char('+') => {
                if self.last_status.is_none() {
                    self.clear_error();
                    self.pending_interval_secs = self
                        .pending_interval_secs
                        .saturating_add(INTERVAL_STEP_SECS)
                        .min(MAX_INTERVAL_SECS);
                }
            }
            KeyCode::Char('-') => {
                if self.last_status.is_none() {
                    self.clear_error();
                    self.pending_interval_secs = self
                        .pending_interval_secs
                        .saturating_sub(INTERVAL_STEP_SECS)
                        .max(INTERVAL_MIN_SECS);
                }
            }
            KeyCode::Char('x') => {
                if self.last_status.is_some() {
                    self.clear_error();
                    self.mode = UiMode::StopConfirm;
                } else {
                    self.set_error("timer not running".to_string());
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_text_input_key(
        &mut self,
        code: KeyCode,
        value: &mut String,
        is_filter: bool,
    ) -> Result<bool> {
        match code {
            KeyCode::Esc => {
                self.clear_error();
                self.mode = UiMode::Normal;
                Ok(false)
            }
            KeyCode::Enter => {
                if is_filter {
                    self.clear_error();
                    if let Err(error) = self.apply_filter(value.clone()) {
                        self.set_error(format!("apply filter failed: {error}"));
                        return Ok(true);
                    }
                } else {
                    match self.start_timer_from_ui(value.clone()) {
                        Ok(true) => {}
                        Ok(false) => return Ok(true),
                        Err(error) => {
                            self.set_error(format!("start failed: {error}"));
                            return Ok(true);
                        }
                    }
                }
                self.mode = UiMode::Normal;
                Ok(false)
            }
            KeyCode::Backspace => {
                value.pop();
                Ok(true)
            }
            KeyCode::Char(c) => {
                value.push(c);
                Ok(true)
            }
            _ => Ok(true),
        }
    }

    fn handle_stop_confirm_key(&mut self, code: KeyCode) -> Result<bool> {
        match code {
            KeyCode::Esc => {
                self.mode = UiMode::Normal;
            }
            KeyCode::Char('w') => {
                if let Err(error) = stop_timer(true, false, true) {
                    self.set_error(format!("stop as working failed: {error}"));
                } else {
                    self.set_info("stopped as working".to_string());
                }
                self.mode = UiMode::Normal;
            }
            KeyCode::Char('s') => {
                if let Err(error) = stop_timer(false, true, true) {
                    self.set_error(format!("stop as wasting failed: {error}"));
                } else {
                    self.set_info("stopped as wasting".to_string());
                }
                self.mode = UiMode::Normal;
            }
            KeyCode::Char('x') => {
                if let Err(error) = stop_timer(false, false, true) {
                    self.set_error(format!("stop failed: {error}"));
                } else {
                    self.set_info("stopped".to_string());
                }
                self.mode = UiMode::Normal;
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_range_input_key(
        &mut self,
        code: KeyCode,
        start: &mut String,
        end: &mut String,
        editing_end: &mut bool,
    ) -> Result<bool> {
        match code {
            KeyCode::Esc => {
                self.clear_error();
                self.mode = UiMode::Normal;
                Ok(false)
            }
            KeyCode::Tab => {
                *editing_end = !*editing_end;
                Ok(true)
            }
            KeyCode::Backspace => {
                if *editing_end {
                    end.pop();
                } else {
                    start.pop();
                }
                Ok(true)
            }
            KeyCode::Enter => match self.apply_range_from_ui(start.clone(), end.clone()) {
                Ok(true) => {
                    self.mode = UiMode::Normal;
                    Ok(false)
                }
                Ok(false) => Ok(true),
                Err(error) => {
                    self.set_error(format!("apply range failed: {error}"));
                    Ok(true)
                }
            },
            KeyCode::Char(ch) => {
                if *editing_end {
                    end.push(ch);
                } else {
                    start.push(ch);
                }
                Ok(true)
            }
            _ => Ok(true),
        }
    }

    fn apply_filter(&mut self, value: String) -> Result<()> {
        let normalized = value.trim().to_string();
        let info_message = if normalized.is_empty() {
            "topic filter cleared".to_string()
        } else {
            format!("topic filter: {normalized}  (substring/glob, e.g. rust*, *proj)")
        };
        self.topic_filter = if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        };
        self.rebuild_model()?;
        self.set_info(info_message);
        Ok(())
    }

    fn apply_range_from_ui(&mut self, start: String, end: String) -> Result<bool> {
        let start_input = start.trim().to_string();
        let end_input = end.trim().to_string();
        if start_input.is_empty() || end_input.is_empty() {
            self.set_error("range requires both start and end".to_string());
            return Ok(false);
        }

        let today = OffsetDateTime::now_utc().to_offset(self.offset).date();
        let start_date = match parse_range_endpoint(&start_input, today) {
            Ok(d) => d,
            Err(msg) => {
                self.set_error(msg);
                return Ok(false);
            }
        };
        let end_date = match parse_range_endpoint(&end_input, today) {
            Ok(d) => d,
            Err(msg) => {
                self.set_error(msg);
                return Ok(false);
            }
        };

        if end_date < start_date {
            self.set_error("range end must be >= start".to_string());
            return Ok(false);
        }

        self.range_filter = Some(RangeFilter {
            start_date,
            end_date,
            start_input,
            end_input,
        });
        self.clear_error();
        self.rebuild_model()?;
        self.set_info(format!("range: {}..{}", start_date, end_date));
        Ok(true)
    }

    fn clear_range_filter(&mut self) -> Result<()> {
        self.range_filter = None;
        self.rebuild_model()
    }

    fn start_timer_from_ui(&mut self, value: String) -> Result<bool> {
        if self.last_status.is_some() {
            self.set_error("timer already running".to_string());
            return Ok(false);
        }
        let topic = value.trim();
        if topic.is_empty() {
            self.set_error("topic is required".to_string());
            return Ok(false);
        }

        let interval = match validate_interval(self.pending_interval_secs) {
            Ok(interval) => interval,
            Err(error) => {
                self.set_error(error.to_string());
                return Ok(false);
            }
        };

        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(error) => {
                self.set_error(format!("failed to locate executable: {error}"));
                return Ok(false);
            }
        };
        let output = Command::new(exe)
            .arg("start")
            .arg(topic)
            .arg(interval.to_string())
            .output()
            .map_err(|e| TaskBeepError::TimerError(format!("failed to start timer: {e}")));

        let output = match output {
            Ok(output) => output,
            Err(error) => {
                self.set_error(error.to_string());
                return Ok(false);
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = stderr.trim();
            self.set_error(if msg.is_empty() {
                "failed to start timer".to_string()
            } else {
                msg.to_string()
            });
            return Ok(false);
        }

        self.clear_error();
        self.set_info(format!("started: {topic}"));
        Ok(true)
    }

    fn set_error(&mut self, message: String) {
        self.footer_notice = Some(FooterNotice {
            kind: NoticeKind::Error,
            message,
        });
        self.next_status_refresh_ms = 0;
    }

    fn set_info(&mut self, message: String) {
        self.footer_notice = Some(FooterNotice {
            kind: NoticeKind::Info,
            message,
        });
        self.next_status_refresh_ms = 0;
    }

    fn clear_error(&mut self) {
        self.footer_notice = None;
        self.next_status_refresh_ms = 0;
    }

    fn footer_notice_line(&self) -> Line<'_> {
        match &self.footer_notice {
            Some(FooterNotice {
                kind: NoticeKind::Error,
                message,
            }) => Line::from(vec![
                Span::styled(
                    "Error: ",
                    Style::default()
                        .fg(Color::LightRed)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(message.clone(), Style::default().fg(Color::LightRed)),
            ]),
            Some(FooterNotice {
                kind: NoticeKind::Info,
                message,
            }) => Line::from(vec![
                Span::styled(
                    "Info: ",
                    Style::default()
                        .fg(Color::LightCyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(message.clone(), Style::default().fg(Color::LightCyan)),
            ]),
            None => Line::raw(""),
        }
    }

    fn footer_state_line(&self) -> Line<'_> {
        Line::raw(self.timer.state_line.clone())
    }

    fn footer_state_width(&self) -> u16 {
        self.timer
            .state_line
            .chars()
            .count()
            .saturating_add(1)
            .min(u16::MAX as usize) as u16
    }

    fn timer_countdown_lines(&self) -> Vec<Line<'static>> {
        ascii_countdown_lines(self.timer_display_seconds())
            .into_iter()
            .map(Line::raw)
            .collect()
    }

    fn timer_display_seconds(&self) -> u64 {
        let Some(status) = &self.last_status else {
            return self.pending_interval_secs;
        };

        let state = Status::from_u8(status.status);
        let effective_now = if state == Some(Status::Paused) && status.paused_at_ms > 0 {
            status.paused_at_ms
        } else {
            now_ms()
        };
        let elapsed = effective_now
            .saturating_sub(status.session_start_ms)
            .saturating_sub(status.total_paused_ms);
        let remaining_ms = status.interval_ms.saturating_sub(elapsed);
        remaining_ms / 1000
    }

    fn toggle_timer(&mut self) -> Result<String> {
        match get_status() {
            Ok(status) if Status::from_u8(status.status) == Some(Status::Paused) => {
                pause_resume_toggle_quiet(CMD_TOGGLE, "resumed", "resume")?;
                Ok("resumed".to_string())
            }
            Ok(_) => {
                pause_resume_toggle_quiet(CMD_TOGGLE, "paused", "pause")?;
                Ok("paused".to_string())
            }
            Err(_) => Ok("toggle ignored: timer not running".to_string()),
        }
    }

    fn move_horizontal(&mut self, delta_weeks: isize) {
        if self.model.cells.is_empty() {
            return;
        }
        let current_week = self.selected_index / 7;
        let row = self.selected_index % 7;
        let mut week = current_week as isize;
        let max_week = self.model.weeks.saturating_sub(1) as isize;

        loop {
            let next_week = (week + delta_weeks).clamp(0, max_week);
            if next_week == week {
                break;
            }
            week = next_week;
            let idx = week as usize * 7 + row;
            if self.model.cells[idx].in_window {
                self.selected_index = idx;
                break;
            }
        }
    }

    fn move_vertical(&mut self, delta_rows: isize) {
        if self.model.cells.is_empty() {
            return;
        }
        let total = self.model.cells.len() as isize;
        let start = self.selected_index as isize;
        let mut i = start;

        loop {
            i = (i + delta_rows).rem_euclid(total);
            if i == start {
                break;
            }
            if self.model.cells[i as usize].in_window {
                self.selected_index = i as usize;
                break;
            }
        }
    }

    fn selected_date(&self) -> Date {
        self.model.cells[self.selected_index].date
    }

    fn selected_day_lines(&self) -> Vec<Line<'_>> {
        let date = self.selected_date();
        let day = self.model.day_stats.get(&date).cloned().unwrap_or_default();
        let total_ms = day.working_ms + day.wasting_ms;
        let prod_pct = if total_ms == 0 {
            0.0
        } else {
            (day.working_ms as f64 / total_ms as f64) * 100.0
        };

        let mut lines = vec![
            Line::raw(format!("Sessions: {}", day.sessions)),
            Line::raw(format!("Working: {}", DurationDisplay(day.working_ms))),
            Line::raw(format!("Wasting: {}", DurationDisplay(day.wasting_ms))),
            Line::raw(format!("Productive: {:.1}%", prod_pct)),
        ];

        // Per-topic breakdown for this day
        if !day.by_topic.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "Topics",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            let mut topics: Vec<_> = day.by_topic.iter().collect();
            topics.sort_by(|(_, a), (_, b)| b.cmp(a));
            for (topic, ms) in topics {
                lines.push(Line::raw(format!("  {}: {}", topic, DurationDisplay(*ms))));
            }
        }

        lines
    }

    fn streaks_lines(&self) -> Vec<Line<'_>> {
        let mut lines = Vec::new();

        // Per-topic best streaks (>= 2d only, sorted by length desc then latest end).
        let mut topic_streaks: Vec<_> = self.model.topics_best_streak.iter().collect();
        if !topic_streaks.is_empty() {
            topic_streaks.sort_by(|(ta, a), (tb, b)| {
                b.days
                    .cmp(&a.days)
                    .then_with(|| b.end.cmp(&a.end))
                    .then_with(|| ta.cmp(tb))
            });
            lines.push(Line::from(Span::styled(
                "Top topic streaks",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            let max_topic_lines = usize::from(STREAKS_PANEL_HEIGHT.saturating_sub(2))
                .saturating_sub(2)
                .max(1);
            for (topic, s) in topic_streaks.into_iter().take(max_topic_lines) {
                lines.push(Line::raw(format!(
                    "{}: {} days ({} - {})",
                    topic,
                    s.days,
                    short_date(s.start),
                    short_date(s.end)
                )));
            }
        }

        let overall_line = match &self.model.overall_best_streak {
            Some(s) => Line::raw(format!(
                "Overall: {} days ({} - {})",
                s.days,
                short_date(s.start),
                short_date(s.end)
            )),
            None => Line::raw("Overall: -"),
        };

        // Keep overall streak anchored to the bottom row of this fixed-height panel.
        let target_rows = usize::from(STREAKS_PANEL_HEIGHT.saturating_sub(2));
        if target_rows > 0 {
            while lines.len() + 1 < target_rows {
                lines.push(Line::raw(""));
            }
        }
        lines.push(overall_line);

        lines
    }

    fn work_waste_chart_data(&self) -> WorkWasteChartData {
        let days: Vec<_> = self
            .model
            .cells
            .iter()
            .filter(|c| c.in_window)
            .map(|c| {
                let stats = self
                    .model
                    .day_stats
                    .get(&c.date)
                    .cloned()
                    .unwrap_or_default();
                (c.date, stats.working_ms, stats.wasting_ms)
            })
            .collect();

        let hours_per_ms = 1.0 / 3_600_000.0;
        let mut work_points = Vec::with_capacity(days.len());
        let mut waste_points = Vec::with_capacity(days.len());
        let mut max_total_hours = 0.0_f64;

        for (idx, (_, working_ms, wasting_ms)) in days.iter().enumerate() {
            let x = idx as f64;
            let working_h = *working_ms as f64 * hours_per_ms;
            let wasting_h = *wasting_ms as f64 * hours_per_ms;
            let total_h = (*working_ms + *wasting_ms) as f64 * hours_per_ms;
            max_total_hours = max_total_hours.max(total_h);
            if working_h > 0.0 {
                work_points.push((x, working_h));
            }
            if wasting_h > 0.0 {
                waste_points.push((x, wasting_h));
            }
        }

        let x_max = if days.len() > 1 {
            (days.len() - 1) as f64
        } else {
            1.0
        };
        let y_max = max_total_hours.ceil().max(1.0);

        let start_label = days
            .first()
            .map(|(d, _, _)| format!("{:02}/{:02}", d.month() as u8, d.day()))
            .unwrap_or_else(|| "-".to_string());
        let mid_label = days
            .get(days.len().saturating_sub(1) / 2)
            .map(|(d, _, _)| format!("{:02}/{:02}", d.month() as u8, d.day()))
            .unwrap_or_else(|| "-".to_string());
        let end_label = days
            .last()
            .map(|(d, _, _)| format!("{:02}/{:02}", d.month() as u8, d.day()))
            .unwrap_or_else(|| "-".to_string());

        WorkWasteChartData {
            work_points,
            waste_points,
            x_bounds: [0.0, x_max],
            y_bounds: [0.0, y_max],
            x_labels: vec![
                Line::raw(start_label),
                Line::raw(mid_label),
                Line::raw(end_label),
            ],
            y_labels: vec![
                Line::raw("0h"),
                Line::raw(format!("{}h", (y_max / 2.0).round() as u64)),
                Line::raw(format!("{}h", y_max.round() as u64)),
            ],
        }
    }

    fn timer_title(&self) -> Line<'_> {
        match &self.mode {
            UiMode::StartInput { value } => {
                let mut spans = framed_label("Timer");
                spans.extend(framed_prompt(
                    's',
                    format!(" {}_ ", value),
                    Some(enter_span()),
                ));
                spans.extend(framed_hotkey_label('t', "oggle"));
                spans.extend(framed_hotkey_label('x', "stop"));
                spans.extend(framed_time(self.pending_interval_secs));
                Line::from(spans)
            }
            UiMode::StopConfirm => Line::from(vec![
                frame_left(),
                Span::raw("Timer"),
                frame_right(),
                frame_left(),
                hotkey_span('w'),
                Span::raw("working"),
                frame_right(),
                frame_left(),
                hotkey_span('s'),
                Span::raw("wasting"),
                frame_right(),
                frame_left(),
                hotkey_span('x'),
                Span::raw("stop"),
                frame_right(),
            ]),
            _ => {
                if self.last_status.is_none() {
                    let mut spans = framed_label("Timer");
                    spans.extend(framed_hotkey_label('s', "tart"));
                    spans.extend(framed_hotkey_label('t', "oggle"));
                    spans.extend(framed_time(self.pending_interval_secs));
                    Line::from(spans)
                } else {
                    let mut spans = framed_label("Timer");
                    spans.extend(framed_hotkey_label('t', "oggle"));
                    spans.extend(framed_hotkey_label('x', "stop"));
                    Line::from(spans)
                }
            }
        }
    }

    fn heatmap_title(&self) -> Line<'_> {
        let heatmap_label = self.model.title.clone();
        match &self.mode {
            UiMode::RangeInput {
                start,
                end,
                editing_end,
            } => {
                let mut spans = framed_label(&heatmap_label);
                let body = if *editing_end {
                    format!(" {} .. [{}_] ", start, end)
                } else {
                    format!(" [{}_] .. {} ", start, end)
                };
                spans.extend(framed_prompt('r', body, Some(enter_span())));
                if self.topic_filter.is_some() {
                    spans.extend(framed_hotkey_label('d', "el topic"));
                }
                if self.range_filter.is_some() {
                    spans.extend(framed_hotkey_label('c', "lear range"));
                }
                Line::from(spans)
            }
            UiMode::FilterInput { value } => {
                let mut spans = framed_label(&heatmap_label);
                spans.extend(framed_prompt(
                    'f',
                    format!(" {}_ ", value),
                    Some(enter_span()),
                ));
                Line::from(spans)
            }
            _ => {
                let mut spans = framed_label(&heatmap_label);
                if let Some(topic) = &self.topic_filter {
                    spans.extend(vec![
                        frame_left(),
                        hotkey_span('f'),
                        Span::raw(format!(" {} ", topic)),
                        hotkey_span('d'),
                        Span::raw("el"),
                        frame_right(),
                    ]);
                } else {
                    spans.extend(framed_hotkey_label('f', "ilter"));
                }

                if let Some(range) = &self.range_filter {
                    spans.extend(vec![
                        frame_left(),
                        hotkey_span('r'),
                        Span::raw(format!(" {} .. {} ", range.start_input, range.end_input)),
                        hotkey_span('c'),
                        Span::raw("lear"),
                        frame_right(),
                    ]);
                } else {
                    spans.extend(framed_hotkey_label('r', "ange"));
                }

                Line::from(spans)
            }
        }
    }

    fn heatmap_corner_title(&self) -> Line<'_> {
        Line::from(vec![
            frame_left(),
            hotkey_span('←'),
            Span::raw("/"),
            hotkey_span('↓'),
            Span::raw("/"),
            hotkey_span('↑'),
            Span::raw("/"),
            hotkey_span('→'),
            frame_right(),
        ])
    }

    fn timer_corner_title(&self) -> Line<'_> {
        let mut spans = Vec::new();
        spans.extend(vec![
            frame_left(),
            Span::raw("re"),
            hotkey_span('l'),
            Span::raw("oad"),
            frame_right(),
        ]);
        spans.extend(framed_hotkey_label('q', "uit"));
        Line::from(spans)
    }

    fn selected_day_title(&self) -> Line<'_> {
        let date = self.selected_date();
        let weekday = weekday_abbrev(date.weekday());
        Line::from(framed_label(&format!("Selected Day ({weekday}, {date})")))
    }

    fn streaks_title(&self) -> Line<'_> {
        Line::from(framed_label("Streak Highlights"))
    }

    fn daily_chart_title(&self) -> Line<'_> {
        Line::from(framed_label("Working vs Wasting"))
    }

    fn daily_chart_legend_lines(&self) -> Vec<Line<'_>> {
        vec![
            Line::from(Span::styled("work", Style::default().fg(Color::LightGreen))),
            Line::from(Span::styled("waste", Style::default().fg(Color::Yellow))),
        ]
    }
}

fn hotkey_span(c: char) -> Span<'static> {
    Span::styled(
        c.to_string(),
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    )
}

fn enter_span() -> Span<'static> {
    Span::styled(
        "↵",
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    )
}

fn frame_left() -> Span<'static> {
    Span::styled("─┐", Style::default())
}

fn frame_right() -> Span<'static> {
    Span::styled("┌─", Style::default())
}

fn framed_hotkey_label(key: char, label_rest: &str) -> Vec<Span<'static>> {
    vec![
        frame_left(),
        hotkey_span(key),
        Span::raw(label_rest.to_string()),
        frame_right(),
    ]
}

fn framed_label(label: &str) -> Vec<Span<'static>> {
    vec![frame_left(), Span::raw(label.to_string()), frame_right()]
}

fn framed_prompt(key: char, body: String, tail: Option<Span<'static>>) -> Vec<Span<'static>> {
    let mut spans = vec![frame_left(), hotkey_span(key), Span::raw(body)];
    if let Some(tail) = tail {
        spans.push(tail);
    }
    spans.push(frame_right());
    spans
}

fn framed_time(seconds: u64) -> Vec<Span<'static>> {
    vec![
        frame_left(),
        hotkey_span('-'),
        Span::raw(format!(" {} ", format_interval_short(seconds))),
        hotkey_span('+'),
        frame_right(),
    ]
}

fn format_interval_short(seconds: u64) -> String {
    let minutes = seconds / 60;
    let remaining_seconds = seconds % 60;

    match (minutes, remaining_seconds) {
        (0, secs) => format!("{}s", secs),
        (mins, 0) => format!("{}m", mins),
        (mins, secs) => format!("{}m{}s", mins, secs),
    }
}

fn build_timer_banner() -> (String, Option<StatusResponse>) {
    match get_status() {
        Ok(status) => {
            let state = Status::from_u8(status.status);
            let state_label = match state {
                Some(Status::Running) => "running",
                Some(Status::Paused) => "paused",
                Some(Status::Waiting) => "waiting",
                None => "unknown",
            };

            (
                format!(
                    "State: {} | Topic: {} | Session #{} | Pauses: {}",
                    state_label, status.topic, status.count, status.pause_count,
                ),
                Some(status),
            )
        }
        Err(_) => ("State: idle".to_string(), None),
    }
}

fn ascii_countdown_lines(total_seconds: u64) -> Vec<String> {
    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;
    let text = format!("{}:{:02}", minutes, seconds);
    let mut rows = vec![String::new(); TIMER_FONT_HEIGHT];

    // prepend one blank row of top padding
    let mut result = vec![String::new()];

    for ch in text.chars() {
        let glyph = timer_font_glyph(ch);
        for (row, part) in rows.iter_mut().zip(glyph.iter()) {
            if !row.is_empty() {
                row.push(' ');
            }
            row.push_str(part);
        }
    }

    result.extend(rows);
    result
}

fn build_heatmap_model(
    entries: &[StatsEntry],
    window_start: Date,
    window_end: Date,
    title: String,
    offset: UtcOffset,
) -> Result<HeatmapModel> {
    let aggregation = build_heat_aggregation(entries, window_start, window_end, offset)?;
    let grid = aggregation.grid;
    let day_stats = aggregation.day_stats;
    let per_topic_days = aggregation.per_topic_days;

    let mut topics_best_streak = HashMap::new();
    for (topic, topic_days) in per_topic_days {
        if let Some(info) = best_streak_for_days(&topic_days, window_start, window_end) {
            topics_best_streak.insert(topic, info);
        }
    }
    let overall_best_streak = best_streak_overall(&day_stats, window_start, window_end);

    Ok(HeatmapModel {
        title,
        weeks: grid.weeks,
        max_working_ms: grid.max_working_ms,
        cells: grid.cells,
        day_stats,
        topics_best_streak,
        overall_best_streak,
    })
}

/// Returns the best streak (≥ 2 days) over [start, end].
/// On ties picks the most-recent (latest end date).
fn best_streak_for_days(days: &HashMap<Date, bool>, start: Date, end: Date) -> Option<StreakInfo> {
    let mut best: Option<StreakInfo> = None;
    let mut cur_start: Option<Date> = None;
    let mut cur = 0u32;
    let mut d = start;

    let try_update = |cur: u32, run_start: Date, run_end: Date, best: &mut Option<StreakInfo>| {
        if cur < 2 {
            return;
        }
        let candidate = StreakInfo {
            days: cur,
            start: run_start,
            end: run_end,
        };
        let update = match best {
            None => true,
            Some(b) => cur > b.days || (cur == b.days && candidate.end >= b.end),
        };
        if update {
            *best = Some(candidate);
        }
    };

    while d <= end {
        if days.get(&d).copied().unwrap_or(false) {
            if cur_start.is_none() {
                cur_start = Some(d);
            }
            cur += 1;
        } else {
            if let Some(s) = cur_start.take() {
                try_update(cur, s, d - TimeDuration::days(1), &mut best);
            }
            cur = 0;
        }
        d += TimeDuration::days(1);
    }
    // flush trailing run
    if let Some(s) = cur_start {
        try_update(cur, s, end, &mut best);
    }
    best
}

/// Best streak over the entire year range for overall (all productive days).
fn best_streak_overall(
    day_stats: &HashMap<Date, DayStats>,
    jan_1: Date,
    dec_31: Date,
) -> Option<StreakInfo> {
    let days: HashMap<Date, bool> = day_stats
        .iter()
        .filter(|(_, s)| s.working_ms > 0)
        .map(|(d, _)| (*d, true))
        .collect();
    best_streak_for_days(&days, jan_1, dec_31)
}

fn short_date(date: Date) -> String {
    format!("{} {}", month_abbrev(date.month()), date.day())
}

fn render_month_line(model: &HeatmapModel) -> Line<'_> {
    let pairs: Vec<(Date, bool)> = model.cells.iter().map(|c| (c.date, c.in_window)).collect();
    let s = crate::utils::month_label_chars(&pairs, model.weeks, 4, 2);
    Line::styled(s, Style::default().fg(Color::DarkGray))
}

fn level_style(level: u8, accent: HeatmapAccent) -> Style {
    match level {
        0 => Style::default().fg(Color::Indexed(236)),
        1 => Style::default()
            .fg(accent.base_ui_color())
            .add_modifier(Modifier::DIM),
        2 => Style::default().fg(accent.base_ui_color()),
        3 => Style::default()
            .fg(accent.base_ui_color())
            .add_modifier(Modifier::BOLD),
        _ => Style::default()
            .fg(accent.bright_ui_color())
            .add_modifier(Modifier::BOLD),
    }
}

fn level_glyph(level: u8) -> char {
    match level {
        0 => '·',
        _ => '■',
    }
}

fn year_window(year: i32) -> Result<(Date, Date, String)> {
    let start = Date::from_calendar_date(year, Month::January, 1)
        .map_err(|e| TaskBeepError::StatsError(format!("invalid year {year}: {e}")))?;
    let end = Date::from_calendar_date(year, Month::December, 31)
        .map_err(|e| TaskBeepError::StatsError(format!("invalid year {year}: {e}")))?;
    Ok((start, end, format!("Heatmap ({year})")))
}

fn parse_range_endpoint(input: &str, today: Date) -> std::result::Result<Date, String> {
    let value = input.trim();
    if let Some(days_str) = value.strip_prefix("~d") {
        let days: i64 = days_str
            .parse()
            .map_err(|_| format!("invalid day offset '{}': use ~dN", value))?;
        return Ok(today - TimeDuration::days(days));
    }
    if let Some(months_str) = value.strip_prefix("~m") {
        let months: u32 = months_str
            .parse()
            .map_err(|_| format!("invalid month offset '{}': use ~mN", value))?;
        return shift_months_with_day(today, months)
            .ok_or_else(|| format!("invalid month offset '{}': out of range", value));
    }
    parse_calendar_date(value)
        .ok_or_else(|| format!("invalid date '{}': expected YYYY-M-D, ~dN, or ~mN", value))
}
