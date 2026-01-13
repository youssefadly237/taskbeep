use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

const DEFAULT_SESSION_DURATION: u64 = 1500;
const DEFAULT_VOLUME: f32 = 0.4;
const DEFAULT_BEEP_FREQUENCY: f32 = 2048.0;
const DEFAULT_FIRST_BEEP_DURATION: f32 = 0.08;
const DEFAULT_SECOND_BEEP_DURATION: f32 = 0.12;
const DEFAULT_GAP_DURATION: f32 = 0.09;
const DEFAULT_PAUSE_DURATION: f32 = 0.7;
const DEFAULT_RESPONSE_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default session duration in seconds (default: 1500s / 25 minutes)
    #[serde(default = "default_session_duration")]
    pub session_duration: u64,

    /// Audio volume (0.0 to 1.0, default: 0.4)
    #[serde(default = "default_volume")]
    pub volume: f32,

    /// Beep frequency in Hz (default: 2048.0)
    #[serde(default = "default_beep_frequency")]
    pub beep_frequency: f32,

    /// First beep duration in seconds (default: 0.08)
    #[serde(default = "default_first_beep_duration")]
    pub first_beep_duration: f32,

    /// Second beep duration in seconds (default: 0.12)
    #[serde(default = "default_second_beep_duration")]
    pub second_beep_duration: f32,

    /// Gap between beeps in seconds (default: 0.09)
    #[serde(default = "default_gap_duration")]
    pub gap_duration: f32,

    /// Pause after pattern in seconds (default: 0.7)
    #[serde(default = "default_pause_duration")]
    pub pause_duration: f32,

    /// Response timeout in seconds (default: 300 / 5 minutes, 0 = no timeout)
    #[serde(
        default = "default_response_timeout_secs",
        deserialize_with = "deserialize_response_timeout"
    )]
    pub response_timeout_secs: Option<u64>,

    /// Optional script to run when timer finishes (after beep)
    #[serde(default)]
    pub on_timer_finish: Option<String>,
}

fn default_session_duration() -> u64 {
    DEFAULT_SESSION_DURATION
}
fn default_volume() -> f32 {
    DEFAULT_VOLUME
}
fn default_beep_frequency() -> f32 {
    DEFAULT_BEEP_FREQUENCY
}
fn default_first_beep_duration() -> f32 {
    DEFAULT_FIRST_BEEP_DURATION
}
fn default_second_beep_duration() -> f32 {
    DEFAULT_SECOND_BEEP_DURATION
}
fn default_gap_duration() -> f32 {
    DEFAULT_GAP_DURATION
}
fn default_pause_duration() -> f32 {
    DEFAULT_PAUSE_DURATION
}
fn default_response_timeout_secs() -> Option<u64> {
    Some(DEFAULT_RESPONSE_TIMEOUT_SECS)
}

fn deserialize_response_timeout<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = Option::<u64>::deserialize(deserializer)?;
    Ok(val.filter(|&v| v > 0))
}

impl Default for Config {
    fn default() -> Self {
        Self {
            session_duration: default_session_duration(),
            volume: default_volume(),
            beep_frequency: default_beep_frequency(),
            first_beep_duration: default_first_beep_duration(),
            second_beep_duration: default_second_beep_duration(),
            gap_duration: default_gap_duration(),
            pause_duration: default_pause_duration(),
            response_timeout_secs: default_response_timeout_secs(),
            on_timer_finish: None,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.session_duration == 0 {
            return Err("session_duration must be greater than 0".to_string());
        }
        if self.session_duration > 86400 {
            return Err("session_duration cannot exceed 86400 seconds (24 hours)".to_string());
        }
        if !self.volume.is_finite() || self.volume < 0.0 || self.volume > 1.0 {
            return Err("volume must be a finite number between 0.0 and 1.0".to_string());
        }
        if !self.beep_frequency.is_finite() || self.beep_frequency <= 0.0 {
            return Err("beep_frequency must be a finite positive number".to_string());
        }
        if !self.first_beep_duration.is_finite() || self.first_beep_duration <= 0.0 {
            return Err("first_beep_duration must be a finite positive number".to_string());
        }
        if !self.second_beep_duration.is_finite() || self.second_beep_duration <= 0.0 {
            return Err("second_beep_duration must be a finite positive number".to_string());
        }
        if !self.gap_duration.is_finite() || self.gap_duration < 0.0 {
            return Err("gap_duration must be a finite non-negative number".to_string());
        }
        if !self.pause_duration.is_finite() || self.pause_duration < 0.0 {
            return Err("pause_duration must be a finite non-negative number".to_string());
        }
        if let Some(timeout) = self.response_timeout_secs
            && timeout > 86400
        {
            return Err("response_timeout_secs cannot exceed 86400 seconds (24 hours)".to_string());
        }

        // Validate script path
        if let Some(script_path) = &self.on_timer_finish {
            let path = PathBuf::from(script_path);

            // Require absolute paths to prevent confusion
            if !path.is_absolute() {
                return Err("on_timer_finish must be an absolute path".to_string());
            }

            // Check if file exists
            if !path.exists() {
                return Err(format!(
                    "on_timer_finish script does not exist: {}",
                    script_path
                ));
            }

            // Check if executable (Unix-specific)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                let metadata = std::fs::metadata(&path)
                    .map_err(|e| format!("Cannot read script metadata: {}", e))?;

                let mode = metadata.permissions().mode();

                if mode & 0o111 == 0 {
                    return Err(format!(
                        "on_timer_finish script is not executable: {}",
                        script_path
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn config_path() -> PathBuf {
        let config_dir = if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg_config)
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config")
        } else {
            // Fallback for environments without XDG_CONFIG_HOME or HOME set
            // Uses .config relative to current directory (e.g., containers, CI)
            PathBuf::from(".config")
        };

        config_dir.join("taskbeep").join("config.toml")
    }

    /// Load configuration from file, creating default if it doesn't exist
    pub fn load() -> Self {
        let config_path = Self::config_path();

        if let Ok(contents) = fs::read_to_string(&config_path) {
            match toml::from_str::<Config>(&contents) {
                Ok(config) => {
                    if let Err(e) = config.validate() {
                        eprintln!("Warning: Invalid config: {}", e);
                        eprintln!("Using default configuration");
                        Config::default()
                    } else {
                        config
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to parse config file: {}", e);
                    eprintln!("Using default configuration");
                    Config::default()
                }
            }
        } else {
            let config = Config::default();
            if let Err(e) = config.create_default_file() {
                eprintln!("Warning: Failed to create default config file: {}", e);
            }
            config
        }
    }

    fn create_default_file(&self) -> std::io::Result<()> {
        let config_path = Self::config_path();

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        const TEMPLATE: &str = include_str!("../config.toml.template");
        fs::write(config_path, TEMPLATE)?;
        Ok(())
    }

    pub fn reset() -> std::io::Result<()> {
        let config = Config::default();
        config.create_default_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_session_duration_zero() {
        let config = Config {
            session_duration: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_session_duration_exceeds_max() {
        let config = Config {
            session_duration: 86401,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_session_duration_at_max() {
        let config = Config {
            session_duration: 86400,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_volume_negative() {
        let config = Config {
            volume: -0.1,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_volume_exceeds_max() {
        let config = Config {
            volume: 1.1,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_volume_nan() {
        let config = Config {
            volume: f32::NAN,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_volume_infinity() {
        let config = Config {
            volume: f32::INFINITY,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_beep_frequency_zero() {
        let config = Config {
            beep_frequency: 0.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_beep_frequency_negative() {
        let config = Config {
            beep_frequency: -100.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_beep_frequency_nan() {
        let config = Config {
            beep_frequency: f32::NAN,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_first_beep_duration_zero() {
        let config = Config {
            first_beep_duration: 0.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_first_beep_duration_negative() {
        let config = Config {
            first_beep_duration: -0.1,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_gap_duration_negative() {
        let config = Config {
            gap_duration: -0.1,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_gap_duration_zero_is_valid() {
        let config = Config {
            gap_duration: 0.0,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_pause_duration_nan() {
        let config = Config {
            pause_duration: f32::NAN,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
}
