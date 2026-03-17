mod audio;
mod commands;
mod config;
mod error;
mod heatmap;
mod protocol;
mod stats;
mod timer;
#[cfg(feature = "ui")]
mod ui;
mod utils;

use clap::{Parser, Subcommand};
use config::Config;
use std::{path::PathBuf, sync::OnceLock};

use crate::commands::{pause_resume_toggle, send_signal, show_status, stop_timer};
use crate::error::TaskBeepError;
use crate::protocol::{CMD_PAUSE, CMD_RESUME, CMD_TOGGLE, Status, get_status};
use crate::stats::{clear_stats, export_stats, show_stats};
use crate::timer::start_timer;
#[cfg(feature = "ui")]
use crate::ui::run_ui;

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
        /// Only show stats for this topic
        topic: Option<String>,
        /// Show day stats; optional offset: ^ or ~N (e.g. -d ^, -d ~3)
        #[arg(short = 'd', long, num_args = 0..=1, default_missing_value = "0", value_name = "OFFSET")]
        day: Option<String>,
        /// Show week stats; optional offset: ^ or ~N (e.g. -w ^, -w ~2)
        #[arg(short = 'w', long, num_args = 0..=1, default_missing_value = "0", value_name = "OFFSET")]
        week: Option<String>,
        /// Show month stats; optional offset: ^ or ~N (e.g. -m ^, -m ~3)
        #[arg(short = 'm', long, num_args = 0..=1, default_missing_value = "0", value_name = "OFFSET")]
        month: Option<String>,
        /// Show year stats; accepts a year or offset: -y 2025, -y ^, -y ~1
        #[arg(short = 'y', long, num_args = 0..=1, default_missing_value = "0", value_name = "YEAR_OR_OFFSET")]
        year: Option<String>,
        /// Explicit date range (inclusive): YYYY-M-D..YYYY-M-D
        #[arg(long, value_name = "START..END")]
        range: Option<String>,
        /// Print a GitHub-style time heatmap
        #[arg(long)]
        heatmap: bool,
    },
    /// Open interactive one-page terminal UI
    Ui,
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
        Commands::Stop { working, wasting } => stop_timer(working, wasting, false),
        Commands::Pause => pause_resume_toggle(CMD_PAUSE, "paused", "pause"),
        Commands::Resume => pause_resume_toggle(CMD_RESUME, "resumed", "resume"),
        Commands::Toggle => match get_status() {
            Ok(status) if Status::from_u8(status.status) == Some(Status::Paused) => {
                pause_resume_toggle(CMD_TOGGLE, "resumed", "resume")
            }
            Ok(_) => pause_resume_toggle(CMD_TOGGLE, "paused", "pause"),
            Err(e) => Err(e),
        },
        Commands::Status { format } => show_status(&format),
        Commands::Working => send_signal(true),
        Commands::Wasting => send_signal(false),
        Commands::Stats {
            topic,
            day,
            week,
            month,
            year,
            range,
            heatmap,
        } => show_stats(
            topic.as_deref(),
            day.as_deref(),
            week.as_deref(),
            month.as_deref(),
            year.as_deref(),
            range.as_deref(),
            heatmap,
        ),
        Commands::Ui => launch_ui(),
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

#[cfg(feature = "ui")]
fn launch_ui() -> crate::error::Result<()> {
    run_ui()
}

#[cfg(not(feature = "ui"))]
fn launch_ui() -> crate::error::Result<()> {
    Err(TaskBeepError::ConfigError(
        "UI support is disabled in this build. Rebuild with: cargo build --features ui".to_string(),
    ))
}
