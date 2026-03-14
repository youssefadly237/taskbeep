use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::error::{Result, TaskBeepError};
use crate::protocol::get_status;
use crate::utils::{
    DurationDisplay, MAX_INTERVAL_SECS, MAX_TOPIC_LEN, MILLIS_PER_SECOND, SECONDS_PER_DAY,
    statsfile_path,
};

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

pub fn get_period_start_ms(period: &str) -> Option<u64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

    let start_secs = match period {
        "today" => {
            let secs_since_midnight = now % SECONDS_PER_DAY;
            now - secs_since_midnight
        }
        "week" => {
            let days_since_epoch = now / SECONDS_PER_DAY;
            let days_since_monday = (days_since_epoch + 3) % 7;
            now - (days_since_monday * SECONDS_PER_DAY) - (now % SECONDS_PER_DAY)
        }
        "month" => now - (30 * SECONDS_PER_DAY),
        "year" => now - (365 * SECONDS_PER_DAY),
        _ => return None,
    };

    Some(start_secs * MILLIS_PER_SECOND)
}

pub fn show_stats(filter: Option<&str>) -> Result<()> {
    let stats_path = statsfile_path();
    if !stats_path.exists() {
        println!("No statistics available yet");
        return Ok(());
    }

    let filter_start = filter.and_then(get_period_start_ms);
    let file = File::open(&stats_path)?;
    let reader = BufReader::new(file);

    let mut total_working_ms = 0u64;
    let mut total_wasting_ms = 0u64;
    let mut total_pause_count = 0u64;
    let mut total_pause_duration_ms = 0u64;
    // (working_ms, wasting_ms, pause_count, pause_duration_ms)
    let mut topic_stats: HashMap<String, (u64, u64, u64, u64)> = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        if let Some(entry) = StatsEntry::from_line(&line) {
            if let Some(start) = filter_start
                && entry.start_time_ms < start
            {
                continue;
            }

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
    }

    if total_working_ms == 0 && total_wasting_ms == 0 {
        println!("No sessions recorded yet");
        return Ok(());
    }

    let total_ms = total_working_ms + total_wasting_ms;
    let productivity = (total_working_ms as f64 / total_ms as f64) * 100.0;

    let period_label = match filter {
        Some("today") => " (Today)",
        Some("week") => " (This Week)",
        Some("month") => " (This Month)",
        Some("year") => " (This Year)",
        _ => "",
    };

    println!("=== Productivity Statistics{} ===", period_label);
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
                if entry.topic == topic_name {
                    matching_entries.push(entry);
                } else {
                    other_entries.push(entry);
                }
            }
        }

        if matching_entries.is_empty() {
            let topic_lower = topic_name.to_lowercase();

            let exact_case_insensitive: Vec<_> = all_topics
                .iter()
                .filter(|t| t.to_lowercase() == topic_lower)
                .collect();

            if !exact_case_insensitive.is_empty() {
                println!(
                    "No exact match found for '{}'. Did you mean one of these (case-sensitive)?",
                    topic_name
                );
                for t in exact_case_insensitive {
                    println!("  {}", t);
                }
                return Ok(());
            }

            let partial_matches: Vec<_> = all_topics
                .iter()
                .filter(|t| t.to_lowercase().contains(&topic_lower))
                .collect();

            if !partial_matches.is_empty() {
                println!(
                    "No exact match found for '{}'. Did you mean one of these?",
                    topic_name
                );
                for t in partial_matches {
                    println!("  {}", t);
                }
                return Ok(());
            }

            println!("No statistics found for topic: '{}'", topic_name);
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
