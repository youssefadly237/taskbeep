use std::{
    collections::HashSet,
    env,
    io::{self, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use time::{Date, Duration, Month, OffsetDateTime, UtcOffset};

use crate::error::{Result, TaskBeepError};

// Time constants
pub const MILLIS_PER_SECOND: u64 = 1000;
pub const SECONDS_PER_MINUTE: u64 = 60;
pub const SECONDS_PER_HOUR: u64 = 3600;
pub const SECONDS_PER_DAY: u64 = 86400;

// File / socket names
pub const SOCKET_NAME: &str = "taskbeep.sock";
pub const STATS_FILE_NAME: &str = ".taskbeep.stats";

// Validation limits
pub const MIN_INTERVAL_SECS: u64 = 1;
pub const MAX_INTERVAL_SECS: u64 = SECONDS_PER_DAY;
pub const MAX_TOPIC_LEN: usize = 255;
pub const HEATMAP_LEVELS: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeatmapAccent {
    Green,
    Red,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
}

impl HeatmapAccent {
    pub fn from_env() -> Self {
        match env::var("TASKBEEP_HEATMAP_ACCENT") {
            Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
                "red" => Self::Red,
                "yellow" => Self::Yellow,
                "blue" => Self::Blue,
                "magenta" => Self::Magenta,
                "cyan" => Self::Cyan,
                "white" => Self::White,
                _ => Self::Green,
            },
            Err(_) => Self::Green,
        }
    }

    pub fn base_ansi_code(self) -> u8 {
        match self {
            Self::Red => 31,
            Self::Green => 32,
            Self::Yellow => 33,
            Self::Blue => 34,
            Self::Magenta => 35,
            Self::Cyan => 36,
            Self::White => 37,
        }
    }

    pub fn bright_ansi_code(self) -> u8 {
        match self {
            Self::Red => 91,
            Self::Green => 92,
            Self::Yellow => 93,
            Self::Blue => 94,
            Self::Magenta => 95,
            Self::Cyan => 96,
            Self::White => 97,
        }
    }

    #[cfg(feature = "ui")]
    pub fn base_ui_color(self) -> ratatui::style::Color {
        match self {
            Self::Red => ratatui::style::Color::Red,
            Self::Green => ratatui::style::Color::Green,
            Self::Yellow => ratatui::style::Color::Yellow,
            Self::Blue => ratatui::style::Color::Blue,
            Self::Magenta => ratatui::style::Color::Magenta,
            Self::Cyan => ratatui::style::Color::Cyan,
            Self::White => ratatui::style::Color::Gray,
        }
    }

    #[cfg(feature = "ui")]
    pub fn bright_ui_color(self) -> ratatui::style::Color {
        match self {
            Self::Red => ratatui::style::Color::LightRed,
            Self::Green => ratatui::style::Color::LightGreen,
            Self::Yellow => ratatui::style::Color::LightYellow,
            Self::Blue => ratatui::style::Color::LightBlue,
            Self::Magenta => ratatui::style::Color::LightMagenta,
            Self::Cyan => ratatui::style::Color::LightCyan,
            Self::White => ratatui::style::Color::White,
        }
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before UNIX epoch")
        .as_millis() as u64
}

pub struct DurationDisplay(pub u64);

impl std::fmt::Display for DurationDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let secs = self.0 / MILLIS_PER_SECOND;
        if secs == 0 {
            return write!(f, "0s");
        }

        let h = secs / SECONDS_PER_HOUR;
        let m = (secs % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
        let s = secs % SECONDS_PER_MINUTE;

        let mut first = true;

        if h > 0 {
            write!(f, "{}h", h)?;
            first = false;
        }
        if m > 0 {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "{}m", m)?;
            first = false;
        }
        if s > 0 || first {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "{}s", s)?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub fn format_duration(ms: u64) -> String {
    DurationDisplay(ms).to_string()
}

pub fn get_runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

pub fn socket_path() -> PathBuf {
    get_runtime_dir().join(SOCKET_NAME)
}

pub fn statsfile_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(STATS_FILE_NAME)
    } else {
        get_runtime_dir().join(STATS_FILE_NAME)
    }
}

pub fn validate_topic(topic: &str) -> Result<String> {
    if topic.is_empty() {
        return Err(TaskBeepError::ConfigError(
            "Topic cannot be empty".to_string(),
        ));
    }
    if topic.len() > MAX_TOPIC_LEN {
        return Err(TaskBeepError::ConfigError(format!(
            "Topic too long (max {} characters)",
            MAX_TOPIC_LEN
        )));
    }
    if topic.contains(&['\0', '\n', '\r', '\t'][..]) {
        return Err(TaskBeepError::ConfigError(
            "Topic contains invalid characters".to_string(),
        ));
    }
    Ok(topic.to_string())
}

pub fn validate_interval(interval: u64) -> Result<u64> {
    if interval < MIN_INTERVAL_SECS {
        return Err(TaskBeepError::ConfigError(format!(
            "Interval too short (min {}s)",
            MIN_INTERVAL_SECS
        )));
    }
    if interval > MAX_INTERVAL_SECS {
        return Err(TaskBeepError::ConfigError(format!(
            "Interval too long (max {}s)",
            MAX_INTERVAL_SECS
        )));
    }
    Ok(interval)
}

pub fn confirm(prompt: &str) -> Result<bool> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

pub fn local_date_from_ms(timestamp_ms: u64, offset: UtcOffset) -> Result<Date> {
    let timestamp_ns = i128::from(timestamp_ms) * 1_000_000;
    let datetime = OffsetDateTime::from_unix_timestamp_nanos(timestamp_ns).map_err(|error| {
        TaskBeepError::StatsError(format!("invalid stats timestamp {timestamp_ms}: {error}"))
    })?;
    Ok(datetime.to_offset(offset).date())
}

pub fn current_local_date() -> Date {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    OffsetDateTime::now_utc().to_offset(offset).date()
}

pub fn month_abbrev(month: Month) -> &'static str {
    match month {
        Month::January => "Jan",
        Month::February => "Feb",
        Month::March => "Mar",
        Month::April => "Apr",
        Month::May => "May",
        Month::June => "Jun",
        Month::July => "Jul",
        Month::August => "Aug",
        Month::September => "Sep",
        Month::October => "Oct",
        Month::November => "Nov",
        Month::December => "Dec",
    }
}

/// Build the month-label header row for a heatmap grid.
///
/// `cell_dates` holds `weeks * 7` `(date, in_window)` pairs ordered
/// column-major (index = `week * 7 + row`).  `base_col` is the number of
/// leading spaces before the first week column (4 for the day-name prefix).
/// `cell_width` is the character width of one week column (2 for most heatmaps).
///
/// Returns a `String` of spaces with 3-character month abbreviations placed at
/// the first week column that contains the 1st day of each month.
pub fn month_label_chars(
    cell_dates: &[(Date, bool)],
    weeks: usize,
    base_col: usize,
    cell_width: usize,
) -> String {
    let total_width = base_col + weeks * cell_width;
    let mut chars = vec![' '; total_width];
    let mut seen: HashSet<(i32, u8)> = HashSet::new();

    for week in 0..weeks {
        for row in 0..7 {
            let idx = week * 7 + row;
            if idx >= cell_dates.len() {
                break;
            }
            let (date, in_window) = cell_dates[idx];
            if in_window && date.day() == 1 {
                let key = (date.year(), date.month() as u8);
                if seen.insert(key) {
                    let label = month_abbrev(date.month());
                    let col = base_col + week * cell_width;
                    for (offset, c) in label.chars().enumerate() {
                        if col + offset < chars.len() {
                            chars[col + offset] = c;
                        }
                    }
                }
                break;
            }
        }
    }

    chars.into_iter().collect()
}

pub fn day_label(row: usize) -> &'static str {
    match row {
        0 => "Su  ",
        1 => "Mo  ",
        2 => "Tu  ",
        3 => "We  ",
        4 => "Th  ",
        5 => "Fr  ",
        _ => "Sa  ",
    }
}

#[cfg(feature = "ui")]
pub fn weekday_abbrev(weekday: time::Weekday) -> &'static str {
    match weekday {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    }
}

/// Returns true when `topic` matches `pattern`.
///
/// Matching rules:
/// - `=exact`  — prefix `=` forces a case-sensitive exact match
/// - `glob*`   — contains `*` or `?` -> case-insensitive glob match
/// - `substr`  — otherwise -> case-insensitive substring match
pub fn topic_matches(pattern: &str, topic: &str) -> bool {
    if let Some(exact) = pattern.strip_prefix('=') {
        topic == exact
    } else {
        let pat = pattern.to_lowercase();
        let text = topic.to_lowercase();
        if pat.contains('*') || pat.contains('?') {
            wildcard_match(&pat, &text)
        } else {
            text.contains(pat.as_str())
        }
    }
}

/// Classic DP wildcard matcher: `*` matches any sequence, `?` matches one char.
fn wildcard_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (m, n) = (p.len(), t.len());
    let mut dp = vec![vec![false; n + 1]; m + 1];
    dp[0][0] = true;
    for i in 1..=m {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }
    for i in 1..=m {
        for j in 1..=n {
            if p[i - 1] == '*' {
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
            } else if p[i - 1] == '?' || p[i - 1] == t[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            }
        }
    }
    dp[m][n]
}

/// Heatmap intensity level (0–HEATMAP_LEVELS) from working ms and maximum ms.
/// Uses sqrt normalisation so mid-range values stay visible.
pub fn heatmap_intensity(working_ms: u64, max_working_ms: u64) -> u8 {
    if working_ms == 0 || max_working_ms == 0 {
        return 0;
    }
    let normalized = (working_ms as f64 / max_working_ms as f64).sqrt();
    let scaled = (normalized * HEATMAP_LEVELS as f64).ceil();
    scaled.clamp(1.0, HEATMAP_LEVELS as f64) as u8
}

/// Shared heatmap cell-level selection for both CLI and TUI renderers.
pub fn heatmap_cell_level(working_ms: u64, max_working_ms: u64, in_window: bool) -> Option<u8> {
    if !in_window {
        return None;
    }
    Some(heatmap_intensity(working_ms, max_working_ms))
}

/// Legend levels derived from max working time using the same sqrt curve.
pub fn heatmap_legend_levels(max_working_ms: u64) -> [u8; (HEATMAP_LEVELS as usize) + 1] {
    let mut levels = [0u8; (HEATMAP_LEVELS as usize) + 1];
    for level in 0..=HEATMAP_LEVELS {
        let working_ms = if level == 0 {
            0
        } else {
            let fraction = level as f64 / HEATMAP_LEVELS as f64;
            (max_working_ms as f64 * fraction * fraction).round() as u64
        };
        levels[level as usize] = heatmap_intensity(working_ms, max_working_ms);
    }
    levels
}

/// Parse a `YYYY-M-D` calendar date string.
pub fn parse_calendar_date(value: &str) -> Option<Date> {
    let mut parts = value.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month_num: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let month = Month::try_from(month_num).ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

/// Shift `date` by `delta` months, snapping to the 1st of the target month.
pub fn add_months_snap(date: Date, delta: i32) -> Option<Date> {
    let total_months = date.year() * 12 + (date.month() as i32 - 1) + delta;
    let year = total_months.div_euclid(12);
    let month_index = total_months.rem_euclid(12) as u8;
    Date::from_calendar_date(year, Month::try_from(month_index + 1).ok()?, 1).ok()
}

/// Shift `date` back `months_back` months, preserving the day-of-month
/// (clamped to the last valid day of the target month).
#[cfg(feature = "ui")]
pub fn shift_months_with_day(date: Date, months_back: u32) -> Option<Date> {
    let total_months = date.year() * 12 + (date.month() as i32 - 1) - months_back as i32;
    let year = total_months.div_euclid(12);
    let month_index = total_months.rem_euclid(12) as u8;
    let month = Month::try_from(month_index + 1).ok()?;
    let mut day = date.day();
    while day >= 1 {
        if let Ok(candidate) = Date::from_calendar_date(year, month, day) {
            return Some(candidate);
        }
        day -= 1;
    }
    None
}

/// First day of the Sunday-anchored week containing `date`.
pub fn sunday_start_of_week(date: Date) -> Date {
    date - Duration::days(i64::from(date.weekday().number_days_from_sunday()))
}

/// Last day of the Sunday-anchored week containing `date`.
pub fn sunday_end_of_week(date: Date) -> Date {
    let days_from_sunday = date.weekday().number_days_from_sunday();
    date + Duration::days(i64::from(6 - days_from_sunday))
}

/// First day of the Monday-anchored week containing `date`.
pub fn monday_start_of_week(date: Date) -> Date {
    date - Duration::days(i64::from(date.weekday().number_days_from_monday()))
}

/// Parse a period-shift specifier: `0` (current), `^` (1 back), `~N` (N back).
pub fn parse_shift_spec(spec: &str) -> Option<u32> {
    if spec == "0" {
        return Some(0);
    }
    if spec == "^" {
        return Some(1);
    }
    if let Some(rest) = spec.strip_prefix('~') {
        let n: u32 = rest.parse().ok()?;
        return Some(n);
    }
    None
}

/// Parse a `START..END` range using [`parse_shift_spec`] for each side.
/// Returns `(min, max)` regardless of input order.
pub fn parse_shift_range_spec(spec: &str) -> Option<(u32, u32)> {
    let (left_raw, right_raw) = spec.split_once("..")?;
    let left = parse_shift_spec(left_raw.trim())?;
    let right = parse_shift_spec(right_raw.trim())?;
    Some((left.min(right), left.max(right)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration_zero() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(500), "0s");
        assert_eq!(format_duration(999), "0s");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(1_000), "1s");
        assert_eq!(format_duration(5_000), "5s");
        assert_eq!(format_duration(59_000), "59s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(60_000), "1m");
        assert_eq!(format_duration(120_000), "2m");
        assert_eq!(format_duration(90_000), "1m 30s");
        assert_eq!(format_duration(1_500_000), "25m");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3_600_000), "1h");
        assert_eq!(format_duration(7_200_000), "2h");
        assert_eq!(format_duration(3_660_000), "1h 1m");
        assert_eq!(format_duration(3_661_000), "1h 1m 1s");
    }

    #[test]
    fn test_format_duration_complex() {
        assert_eq!(format_duration(3_723_000), "1h 2m 3s");
        assert_eq!(format_duration(7_384_000), "2h 3m 4s");
        assert_eq!(format_duration(86_400_000), "24h");
    }

    #[test]
    fn test_format_duration_no_allocations() {
        let result = format_duration(3_723_000);
        assert_eq!(result, "1h 2m 3s");
        format_duration(0);
        format_duration(1);
        format_duration(u64::MAX / 2);
    }

    #[test]
    fn test_now_ms() {
        let now = now_ms();
        assert!(now > 0);
        let year_2020_ms = 1577836800000u64;
        assert!(now > year_2020_ms);
    }

    // --- topic_matches ---

    #[test]
    fn topic_matches_substring_case_insensitive() {
        assert!(topic_matches("rust", "my-Rust-project"));
        assert!(topic_matches("RUST", "rust"));
        assert!(topic_matches("proj", "my-rust-project"));
    }

    #[test]
    fn topic_matches_substring_no_match() {
        assert!(!topic_matches("python", "my-rust-project"));
    }

    #[test]
    fn topic_matches_glob_star() {
        assert!(topic_matches("rust*", "rust-cli"));
        assert!(topic_matches("*cli", "rust-cli"));
        assert!(topic_matches("*rust*", "my-rust-project"));
        assert!(!topic_matches("rust*", "my-rust-project"));
    }

    #[test]
    fn topic_matches_glob_question_mark() {
        assert!(topic_matches("rus?", "rust"));
        assert!(topic_matches("r?st", "rust"));
        assert!(!topic_matches("rus?", "rustc"));
    }

    #[test]
    fn topic_matches_glob_case_insensitive() {
        assert!(topic_matches("RUST*", "rust-cli"));
        assert!(topic_matches("*CLI", "rust-CLI"));
    }

    #[test]
    fn topic_matches_exact_prefix_case_sensitive() {
        assert!(topic_matches("=rust", "rust"));
        assert!(!topic_matches("=rust", "Rust"));
        assert!(!topic_matches("=rust", "my-rust"));
        assert!(!topic_matches("=rust", "rust-cli"));
    }

    #[test]
    fn topic_matches_exact_empty_after_prefix() {
        // "=" with nothing after it matches only the empty string
        assert!(topic_matches("=", ""));
        assert!(!topic_matches("=", "rust"));
    }

    // --- wildcard_match edge cases ---

    #[test]
    fn wildcard_empty_pattern_matches_empty_text() {
        assert!(topic_matches("*", ""));
        assert!(topic_matches("*", "anything"));
    }

    #[test]
    fn wildcard_pattern_only_star() {
        assert!(topic_matches("*", ""));
        assert!(topic_matches("*", "hello"));
        assert!(topic_matches("*", "hello world"));
    }

    #[test]
    fn wildcard_multiple_consecutive_stars() {
        assert!(topic_matches("**", ""));
        assert!(topic_matches("**", "hello"));
        assert!(topic_matches("a**b", "ab"));
        assert!(topic_matches("a**b", "axyzb"));
        assert!(!topic_matches("a**b", "ba"));
    }

    #[test]
    fn wildcard_question_mark_at_boundaries() {
        assert!(topic_matches("?", "a"));
        assert!(!topic_matches("?", ""));
        assert!(!topic_matches("?", "ab"));
        assert!(topic_matches("?rust", "xrust"));
        assert!(topic_matches("rust?", "rusts"));
        assert!(!topic_matches("rust?", "rust"));
    }

    #[test]
    fn wildcard_empty_text_only_stars_match() {
        assert!(topic_matches("*", ""));
        assert!(topic_matches("***", ""));
        assert!(!topic_matches("a*", ""));
        assert!(!topic_matches("*a", ""));
    }

    // --- heatmap_intensity ---

    #[test]
    fn heatmap_intensity_zero_cases() {
        assert_eq!(heatmap_intensity(0, 100), 0);
        assert_eq!(heatmap_intensity(100, 0), 0);
        assert_eq!(heatmap_intensity(0, 0), 0);
    }

    #[test]
    fn heatmap_intensity_max_is_four() {
        assert_eq!(heatmap_intensity(100, 100), 4);
    }

    #[test]
    fn heatmap_intensity_levels_are_monotone() {
        let max = 3_600_000u64;
        let levels: Vec<u8> = [0, max / 16, max / 4, max * 9 / 16, max]
            .iter()
            .map(|&ms| heatmap_intensity(ms, max))
            .collect();
        for i in 1..levels.len() {
            assert!(
                levels[i] >= levels[i - 1],
                "level {i} should be >= level {}",
                i - 1
            );
        }
    }

    // --- parse_calendar_date ---

    #[test]
    fn parse_calendar_date_valid() {
        use time::Month;
        let d = parse_calendar_date("2026-3-17").unwrap();
        assert_eq!(d.year(), 2026);
        assert_eq!(d.month(), Month::March);
        assert_eq!(d.day(), 17);
    }

    #[test]
    fn parse_calendar_date_invalid() {
        assert!(parse_calendar_date("not-a-date").is_none());
        assert!(parse_calendar_date("2026-13-1").is_none());
        assert!(parse_calendar_date("2026-2-30").is_none());
        assert!(parse_calendar_date("2026-1-1-extra").is_none());
    }

    // --- week-start helpers ---

    #[test]
    fn sunday_start_of_week_returns_sunday() {
        use time::{Month, Weekday};
        let thursday = Date::from_calendar_date(2026, Month::March, 12).unwrap();
        let sun = sunday_start_of_week(thursday);
        assert_eq!(sun.weekday(), Weekday::Sunday);
        assert_eq!(sun.day(), 8);
    }

    #[test]
    fn monday_start_of_week_returns_monday() {
        use time::{Month, Weekday};
        let thursday = Date::from_calendar_date(2026, Month::March, 12).unwrap();
        let mon = monday_start_of_week(thursday);
        assert_eq!(mon.weekday(), Weekday::Monday);
        assert_eq!(mon.day(), 9);
    }

    // --- parse_shift_spec ---

    #[test]
    fn parse_shift_spec_values() {
        assert_eq!(parse_shift_spec("0"), Some(0));
        assert_eq!(parse_shift_spec("^"), Some(1));
        assert_eq!(parse_shift_spec("~5"), Some(5));
        assert_eq!(parse_shift_spec("~0"), Some(0));
        assert_eq!(parse_shift_spec("foo"), None);
        assert_eq!(parse_shift_spec("~abc"), None);
    }

    #[test]
    fn parse_shift_range_spec_ordered() {
        assert_eq!(parse_shift_range_spec("^..~3"), Some((1, 3)));
        assert_eq!(parse_shift_range_spec("~6..~3"), Some((3, 6)));
        assert_eq!(parse_shift_range_spec("0..~2"), Some((0, 2)));
        assert_eq!(parse_shift_range_spec("foo..~2"), None);
    }
}
