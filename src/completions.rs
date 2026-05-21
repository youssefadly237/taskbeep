use std::ffi::OsStr;

use clap::CommandFactory;
use clap_complete::engine::CompletionCandidate;
use clap_complete::env::CompleteEnv;

use crate::Cli;
use crate::stats::read_stats_entries;

fn topic_candidates(current: &str, mut topics: Vec<String>) -> Vec<String> {
    topics.sort();
    topics.dedup();

    if current.is_empty() {
        return topics;
    }

    let current_lower = current.to_lowercase();

    topics
        .into_iter()
        .filter(|t| t.to_lowercase().contains(&current_lower))
        .collect()
}

fn get_all_topics() -> Vec<String> {
    match read_stats_entries(None) {
        Ok(entries) => entries.into_iter().map(|e| e.topic).collect(),
        Err(_) => Vec::new(),
    }
}

pub(crate) fn topic_completer(current: &OsStr) -> Vec<CompletionCandidate> {
    let current = current.to_str().unwrap_or("");
    topic_candidates(current, get_all_topics())
        .into_iter()
        .map(CompletionCandidate::new)
        .collect()
}

pub fn configure_completions() {
    CompleteEnv::with_factory(|| {
        let mut cmd = Cli::command();
        cmd.build();

        // Keep built-in meta entries at the bottom of completion results.
        cmd = cmd
            .mut_arg("help", |arg| arg.display_order(usize::MAX - 1))
            .mut_arg("version", |arg| arg.display_order(usize::MAX));

        cmd = cmd.mut_subcommand("help", |sub| sub.display_order(usize::MAX));
        cmd
    })
    .bin("taskbeep")
    .complete();
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use clap_complete::engine::ArgValueCompleter;

    use crate::Cli;

    use super::topic_candidates;

    #[test]
    fn topic_candidates_are_sorted_and_deduped() {
        let topics = topic_candidates(
            "",
            vec!["beta".to_string(), "alpha".to_string(), "beta".to_string()],
        );

        assert_eq!(topics, vec!["alpha", "beta"]);
    }

    #[test]
    fn topic_candidates_match_case_insensitively() {
        let topics = topic_candidates(
            "AL",
            vec!["alpha".to_string(), "beta".to_string(), "delta".to_string()],
        );

        assert_eq!(topics, vec!["alpha"]);
    }

    #[test]
    fn start_topic_has_custom_completer() {
        let mut command = Cli::command();
        command.build();
        let start = command
            .get_subcommands()
            .find(|cmd: &&clap::Command| cmd.get_name() == "start")
            .expect("start subcommand should exist");
        let topic = start
            .get_positionals()
            .find(|arg: &&clap::Arg| arg.get_index() == Some(1))
            .expect("start topic positional should exist");

        assert!(topic.get::<ArgValueCompleter>().is_some());
    }
}
