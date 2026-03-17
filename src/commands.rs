use std::thread;
use std::time::Duration;

use serde_json::json;

use crate::error::{Result, TaskBeepError};
use crate::protocol::{
    CMD_STOP, CMD_WASTING, CMD_WORKING, RESP_OK, Status, get_status, send_command,
};
use crate::stats::{StatsEntry, append_stats};
use crate::utils::{DurationDisplay, MILLIS_PER_SECOND, now_ms};

/// Stop the active timer session.
///
/// Set `quiet = true` when called from the TUI so that no text is written to
/// stdout (the terminal belongs to the TUI renderer in that case).
pub fn stop_timer(working: bool, wasting: bool, quiet: bool) -> Result<()> {
    let status = get_status()?;
    let status_enum = Status::from_u8(status.status).unwrap_or(Status::Running);

    let should_log = working || wasting;
    let is_working = working;

    if should_log {
        let now = now_ms();

        let (end_time_ms, elapsed_active) = if status_enum == Status::Waiting {
            let end_time = status.session_start_ms + status.interval_ms + status.total_paused_ms;
            (end_time, status.interval_ms)
        } else if status_enum == Status::Paused {
            let elapsed = status
                .paused_at_ms
                .saturating_sub(status.session_start_ms)
                .saturating_sub(status.total_paused_ms);
            (now, elapsed)
        } else {
            let elapsed = now
                .saturating_sub(status.session_start_ms)
                .saturating_sub(status.total_paused_ms);
            (now, elapsed)
        };

        if elapsed_active > MILLIS_PER_SECOND {
            let pause_duration_ms = if status_enum == Status::Paused {
                let current_pause = now.saturating_sub(status.paused_at_ms);
                status.total_paused_ms + current_pause
            } else {
                status.total_paused_ms
            };

            let entry = StatsEntry {
                start_time_ms: status.session_start_ms,
                end_time_ms,
                duration_ms: elapsed_active,
                pause_count: status.pause_count,
                pause_duration_ms,
                topic: status.topic,
                was_working: is_working,
            };
            append_stats(&entry)?;
        }
    }

    let response = send_command(CMD_STOP)?;
    if response.first() == Some(&RESP_OK) {
        if !quiet {
            println!("Timer stopped");
        }
        thread::sleep(Duration::from_millis(100));
        Ok(())
    } else {
        Err(TaskBeepError::TimerError(
            "Failed to stop timer".to_string(),
        ))
    }
}

pub fn show_status(format: &str) -> Result<()> {
    let status = get_status()?;
    let now = now_ms();

    let status_enum = Status::from_u8(status.status).unwrap_or(Status::Running);
    let status_str = match status_enum {
        Status::Paused => "paused",
        Status::Waiting => "waiting",
        Status::Running => "running",
    };

    let target = status.session_start_ms + status.interval_ms + status.total_paused_ms;
    let remaining = if status_enum == Status::Paused {
        target.saturating_sub(status.paused_at_ms)
    } else {
        target.saturating_sub(now)
    };

    let format_lower = format.to_lowercase();
    match format_lower.as_str() {
        "json" => {
            let json_output = json!({
                "status": status_str,
                "topic": status.topic,
                "interval_seconds": status.interval_ms / MILLIS_PER_SECOND,
                "sessions_completed": status.count,
                "remaining_seconds": remaining / MILLIS_PER_SECOND
            });
            println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
        }
        "plain" => {
            println!("status={}", status_str);
            let escaped_topic = status
                .topic
                .replace('\\', "\\\\")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('=', "\\=");
            println!("topic={}", escaped_topic);
            println!(
                "interval_seconds={}",
                status.interval_ms / MILLIS_PER_SECOND
            );
            println!("sessions_completed={}", status.count);
            println!("remaining_seconds={}", remaining / MILLIS_PER_SECOND);
        }
        _ => {
            if !format_lower.is_empty() && format_lower != "human" {
                eprintln!(
                    "Warning: Invalid format '{}', defaulting to 'human'. Valid options: human, json, plain",
                    format
                );
            }
            let human_status = match status_enum {
                Status::Paused => "Paused",
                Status::Waiting => "Waiting for response",
                Status::Running => "Running",
            };
            println!("{}", human_status);
            println!("Topic: {}", status.topic);
            println!("Interval: {}s", status.interval_ms / MILLIS_PER_SECOND);
            println!("Sessions completed: {}", status.count);
            println!("Time remaining: {}", DurationDisplay(remaining));

            if status_enum == Status::Waiting {
                println!("\nRespond with: taskbeep working  OR  taskbeep wasting");
            }
        }
    }

    Ok(())
}

pub fn send_signal(is_working: bool) -> Result<()> {
    let cmd = if is_working { CMD_WORKING } else { CMD_WASTING };
    let response = send_command(cmd)?;

    if response.first() == Some(&RESP_OK) {
        println!(
            "Recorded: {}",
            if is_working { "working" } else { "wasting" }
        );
        Ok(())
    } else {
        match get_status() {
            Ok(status) => {
                let status_enum = Status::from_u8(status.status).unwrap_or(Status::Running);
                if status_enum == Status::Waiting {
                    Err(TaskBeepError::TimerError(
                        "Failed to record response. Please try again.".to_string(),
                    ))
                } else {
                    Err(TaskBeepError::TimerError(
                        "Timer is not waiting for response. Wait for the beep.".to_string(),
                    ))
                }
            }
            Err(_) => Err(TaskBeepError::TimerError("Timer not running".to_string())),
        }
    }
}

fn pause_resume_toggle_impl(
    cmd: u8,
    success_action: &str,
    error_verb: &str,
    quiet: bool,
) -> Result<()> {
    let response = send_command(cmd)?;
    if response.first() == Some(&RESP_OK) {
        if !quiet {
            println!("Timer {}", success_action);
        }
        Ok(())
    } else {
        Err(TaskBeepError::TimerError(format!(
            "Failed to {} timer",
            error_verb
        )))
    }
}

pub fn pause_resume_toggle(cmd: u8, success_action: &str, error_verb: &str) -> Result<()> {
    pause_resume_toggle_impl(cmd, success_action, error_verb, false)
}

#[cfg(feature = "ui")]
pub fn pause_resume_toggle_quiet(cmd: u8, success_action: &str, error_verb: &str) -> Result<()> {
    pause_resume_toggle_impl(cmd, success_action, error_verb, true)
}
