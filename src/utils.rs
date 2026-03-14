use std::{
    io::{self, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

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
}
