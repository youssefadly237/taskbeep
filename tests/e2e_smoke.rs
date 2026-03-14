use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct TestEnv {
    root: PathBuf,
    runtime_dir: PathBuf,
    home_dir: PathBuf,
    stats_path: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();

        let root =
            std::env::temp_dir().join(format!("taskbeep-e2e-{}-{}", std::process::id(), nonce));
        let runtime_dir = root.join("runtime");
        let home_dir = root.join("home");
        let stats_path = home_dir.join(".taskbeep.stats");

        fs::create_dir_all(&runtime_dir).expect("failed to create runtime dir");
        fs::create_dir_all(&home_dir).expect("failed to create home dir");

        Self {
            root,
            runtime_dir,
            home_dir,
            stats_path,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_taskbeep"))
            .args(args)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("HOME", &self.home_dir)
            .output()
            .expect("failed to execute taskbeep")
    }

    fn run_ok(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "command failed: taskbeep {}\nexit: {:?}\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn wait_for_status(&self, expected: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let output = self.run(&["status", "--format", "plain"]);
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout
                    .lines()
                    .any(|l| l.trim() == format!("status={expected}"))
                {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        false
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = self.run(&["stop"]);
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn daemon_socket_cli_smoke_flow() {
    let env = TestEnv::new();

    env.run_ok(&["start", "e2e-smoke", "3", "--response-timeout", "5"]);

    assert!(
        env.wait_for_status("running", Duration::from_secs(3)),
        "timer never reached running status"
    );

    env.run_ok(&["pause"]);
    assert!(
        env.wait_for_status("paused", Duration::from_secs(3)),
        "timer never reached paused status"
    );

    env.run_ok(&["resume"]);
    assert!(
        env.wait_for_status("waiting", Duration::from_secs(15)),
        "timer never reached waiting status"
    );

    env.run_ok(&["working"]);
    env.run_ok(&["stop"]);

    assert!(env.stats_path.exists(), "stats file was not created");

    let stats = fs::read_to_string(&env.stats_path).expect("failed to read stats file");
    let first_line = stats
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("stats file has no entries");

    let field_count = first_line.split('\t').count();
    assert_eq!(
        field_count, 7,
        "stats entry has unexpected field count: {} ({})",
        field_count, first_line
    );
}

#[test]
fn pause_is_rejected_while_waiting() {
    let env = TestEnv::new();

    env.run_ok(&["start", "pause-reject", "1", "--response-timeout", "20"]);
    assert!(
        env.wait_for_status("waiting", Duration::from_secs(15)),
        "timer never reached waiting status"
    );

    let pause = env.run(&["pause"]);
    assert!(
        !pause.status.success(),
        "pause unexpectedly succeeded while waiting"
    );

    assert!(
        env.wait_for_status("waiting", Duration::from_secs(2)),
        "timer left waiting state unexpectedly after pause rejection"
    );

    env.run_ok(&["working"]);
    env.run_ok(&["stop"]);
}

#[test]
fn toggle_is_rejected_while_waiting() {
    let env = TestEnv::new();

    env.run_ok(&["start", "toggle-reject", "1", "--response-timeout", "20"]);
    assert!(
        env.wait_for_status("waiting", Duration::from_secs(15)),
        "timer never reached waiting status"
    );

    let toggle = env.run(&["toggle"]);
    assert!(
        !toggle.status.success(),
        "toggle unexpectedly succeeded while waiting"
    );

    assert!(
        env.wait_for_status("waiting", Duration::from_secs(2)),
        "timer left waiting state unexpectedly after toggle rejection"
    );

    env.run_ok(&["working"]);
    env.run_ok(&["stop"]);
}
