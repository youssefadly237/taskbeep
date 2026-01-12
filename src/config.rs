use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

const DEFAULT_SESSION_DURATION: u64 = 1500;
const DEFAULT_VOLUME: f32 = 0.4;
const DEFAULT_BEEP_FREQUENCY: f32 = 2048.0;
const DEFAULT_FIRST_BEEP_DURATION: f32 = 0.08;
const DEFAULT_SECOND_BEEP_DURATION: f32 = 0.12;
const DEFAULT_GAP_DURATION: f32 = 0.09;
const DEFAULT_PAUSE_DURATION: f32 = 0.7;

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
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.session_duration == 0 {
            return Err("session_duration must be greater than 0".to_string());
        }
        if self.volume < 0.0 || self.volume > 1.0 {
            return Err("volume must be between 0.0 and 1.0".to_string());
        }
        if self.beep_frequency <= 0.0 {
            return Err("beep_frequency must be greater than 0".to_string());
        }
        if self.first_beep_duration <= 0.0 {
            return Err("first_beep_duration must be greater than 0".to_string());
        }
        if self.second_beep_duration <= 0.0 {
            return Err("second_beep_duration must be greater than 0".to_string());
        }
        if self.gap_duration < 0.0 {
            return Err("gap_duration must be non-negative".to_string());
        }
        if self.pause_duration < 0.0 {
            return Err("pause_duration must be non-negative".to_string());
        }
        Ok(())
    }

    pub fn config_path() -> PathBuf {
        let config_dir = if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg_config)
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config")
        } else {
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

    /// Save configuration to file
    pub fn save(&self) -> std::io::Result<()> {
        let config_path = Self::config_path();

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let toml_string = toml::to_string_pretty(self).map_err(std::io::Error::other)?;

        fs::write(config_path, toml_string)?;
        Ok(())
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
