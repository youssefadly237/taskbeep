mod audio;
mod commands;
mod config;
mod error;
mod protocol;
mod stats;
mod timer;
mod utils;

use clap::{Parser, Subcommand};
use config::Config;
use std::{path::PathBuf, sync::OnceLock};

use crate::commands::{pause_resume_toggle, send_signal, show_status, stop_timer};
use crate::error::TaskBeepError;
use crate::protocol::{CMD_PAUSE, CMD_RESUME, CMD_TOGGLE, Status, get_status};
use crate::stats::{clear_stats, export_stats, show_stats};
use crate::timer::start_timer;

static CONFIG: OnceLock<Config> = OnceLock::new();
static AUDIO_DATA: OnceLock<Vec<u8>> = OnceLock::new();

pub fn get_config() -> &'static Config {
    CONFIG.get_or_init(Config::load)
}

pub fn get_audio_data() -> &'static [u8] {
    AUDIO_DATA.get_or_init(|| {
        let config = get_config();
        let audio_config = audio::AudioConfig {
            beep_frequency: config.beep_frequency,
            first_beep_duration: config.first_beep_duration,
            second_beep_duration: config.second_beep_duration,
            gap_duration: config.gap_duration,
            pause_duration: config.pause_duration,
            volume: config.volume,
        };
        audio::generate_beep_audio(&audio_config)
    })
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "TaskBeep - Pomodoro Timer with Productivity Tracking"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a Pomodoro timer with a topic and interval in seconds (configurable default)
    Start {
        /// The topic/task you're working on
        topic: String,
        /// Interval in seconds (default from config or 1500s/25 minutes)
        interval: Option<u64>,
        /// Response timeout in seconds (default from config or 300s, 0 = no timeout)
        #[arg(long)]
        response_timeout: Option<u64>,
    },
    /// Stop and end the timer process
    Stop {
        /// Mark the stopped session as working time
        #[arg(long, conflicts_with = "wasting")]
        working: bool,
        /// Mark the stopped session as wasting time
        #[arg(long, conflicts_with = "working")]
        wasting: bool,
    },
    /// Pause the timer temporarily
    Pause,
    /// Resume the paused timer
    Resume,
    /// Toggle between pause and resume
    Toggle,
    /// Show current timer status
    Status {
        /// Output format: human (default), json, or plain
        #[arg(short, long, default_value = "human")]
        format: String,
    },
    /// Signal that you were working on the topic
    Working,
    /// Signal that you were wasting time
    Wasting,
    /// Show productivity statistics
    Stats {
        /// Show today's stats
        #[arg(short = 'd', long)]
        today: bool,
        /// Show this week's stats
        #[arg(short = 'w', long)]
        week: bool,
        /// Show this month's stats
        #[arg(short = 'm', long)]
        month: bool,
        /// Show this year's stats
        #[arg(short = 'y', long)]
        year: bool,
    },
    /// Export statistics to a file (default: ./taskbeep_stats.tsv)
    Export {
        /// Output file path
        #[arg(default_value = "taskbeep_stats.tsv")]
        output: PathBuf,
    },
    /// Clear statistics (all or for a specific topic)
    Clear {
        /// Optional topic to delete (if omitted, deletes all statistics)
        topic: Option<String>,
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
    /// Manage configuration (show settings, view path, or reset to defaults)
    Config {
        /// Show the path to the config file
        #[arg(long)]
        path: bool,
        /// Reset configuration to defaults
        #[arg(long)]
        reset: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Start {
            topic,
            interval,
            response_timeout,
        } => {
            let interval = interval.unwrap_or_else(|| get_config().session_duration);
            start_timer(topic, interval, response_timeout)
        }
        Commands::Stop { working, wasting } => stop_timer(working, wasting),
        Commands::Pause => pause_resume_toggle(CMD_PAUSE, "paused"),
        Commands::Resume => pause_resume_toggle(CMD_RESUME, "resumed"),
        Commands::Toggle => match get_status() {
            Ok(status) if Status::from_u8(status.status) == Some(Status::Paused) => {
                pause_resume_toggle(CMD_TOGGLE, "resumed")
            }
            Ok(_) => pause_resume_toggle(CMD_TOGGLE, "paused"),
            Err(e) => Err(e),
        },
        Commands::Status { format } => show_status(&format),
        Commands::Working => send_signal(true),
        Commands::Wasting => send_signal(false),
        Commands::Stats {
            today,
            week,
            month,
            year,
        } => {
            let filter = if today {
                Some("today")
            } else if week {
                Some("week")
            } else if month {
                Some("month")
            } else if year {
                Some("year")
            } else {
                None
            };
            show_stats(filter)
        }
        Commands::Export { output } => export_stats(output),
        Commands::Clear { topic, yes } => clear_stats(topic, yes),
        Commands::Config { path, reset } => {
            if reset {
                match Config::reset() {
                    Ok(_) => {
                        println!("Configuration reset to defaults");
                        println!("Config file: {}", Config::config_path().display());
                        Ok(())
                    }
                    Err(e) => Err(TaskBeepError::ConfigError(format!(
                        "Failed to reset config: {}",
                        e
                    ))),
                }
            } else if path {
                let config_path = Config::config_path();
                println!("{}", config_path.display());
                if !config_path.exists() {
                    println!("(file does not exist yet - will be created on first use)");
                }
                Ok(())
            } else {
                println!("Config file: {}", Config::config_path().display());
                println!("\nCurrent configuration:");
                let config = get_config();
                println!(
                    "  session_duration:       {} seconds ({}m)",
                    config.session_duration,
                    config.session_duration / 60
                );
                println!("  volume:                 {} (0.0-1.0)", config.volume);
                println!("  beep_frequency:         {} Hz", config.beep_frequency);
                println!(
                    "  first_beep_duration:    {} seconds",
                    config.first_beep_duration
                );
                println!(
                    "  second_beep_duration:   {} seconds",
                    config.second_beep_duration
                );
                println!("  gap_duration:           {} seconds", config.gap_duration);
                println!(
                    "  pause_duration:         {} seconds",
                    config.pause_duration
                );
                Ok(())
            }
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
