use std::ffi::OsStr;

use clap::CommandFactory;
use clap_complete::engine::CompletionCandidate;
use clap_complete::env::CompleteEnv;

use crate::Cli;
use crate::stats::{read_stats_entries, topics_by_recency};
use crate::utils::topic_matches;

#[cfg(test)]
fn topic_candidates(current: &str, topics: Vec<String>) -> Vec<String> {
    if current.is_empty() {
        return topics;
    }

    topics
        .into_iter()
        .filter(|topic| topic_matches(current, topic))
        .collect()
}

pub(crate) fn topic_completer(current: &OsStr) -> Vec<CompletionCandidate> {
    let current = current.to_str().unwrap_or("");
    match read_stats_entries(None) {
        Ok(entries) => topics_by_recency(&entries)
            .into_iter()
            .filter(|topic| topic_matches(current, topic))
            .map(CompletionCandidate::new)
            .collect(),
        Err(_) => Vec::new(),
    }
}

pub fn configure_completions() {
    CompleteEnv::with_factory(Cli::command)
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
    fn topic_candidates_preserve_input_order() {
        let topics = topic_candidates(
            "",
            vec!["beta".to_string(), "alpha".to_string(), "beta".to_string()],
        );

        assert_eq!(topics, vec!["beta", "alpha", "beta"]);
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
