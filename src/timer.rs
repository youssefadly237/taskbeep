use std::{
    fs,
    io::{Cursor, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use daemonize::Daemonize;
use rodio::{Decoder, OutputStream, OutputStreamBuilder, Sink};

use crate::error::{Result, TaskBeepError};
use crate::protocol::{
    CMD_PAUSE, CMD_RESUME, CMD_STATUS, CMD_STOP, CMD_TOGGLE, CMD_WASTING, CMD_WORKING, RESP_ERROR,
    RESP_OK, Status, StatusResponse,
};
use crate::stats::{StatsEntry, append_stats};
use crate::utils::{
    MILLIS_PER_SECOND, get_runtime_dir, now_ms, socket_path, validate_interval, validate_topic,
};

pub struct PauseState {
    paused_at_ms: Option<u64>,
    total_paused_ms: u64,
    pause_count: u64,
}

impl PauseState {
    pub fn new() -> Self {
        Self {
            paused_at_ms: None,
            total_paused_ms: 0,
            pause_count: 0,
        }
    }

    pub fn is_paused(&self) -> bool {
        self.paused_at_ms.is_some()
    }

    pub fn pause(&mut self, now: u64) {
        if self.paused_at_ms.is_none() {
            self.paused_at_ms = Some(now);
        }
    }

    pub fn resume(&mut self, now: u64) {
        if let Some(paused_at) = self.paused_at_ms {
            let pause_duration = now.saturating_sub(paused_at);
            self.total_paused_ms += pause_duration;
            self.pause_count += 1;
            self.paused_at_ms = None;
        }
    }

    pub fn get_paused_at(&self) -> u64 {
        self.paused_at_ms.unwrap_or(0)
    }

    pub fn get_total_paused(&self) -> u64 {
        self.total_paused_ms
    }

    pub fn get_pause_count(&self) -> u64 {
        self.pause_count
    }
}

pub struct SessionState {
    pub start_ms: u64,
    pub pause_state: PauseState,
}

impl SessionState {
    pub fn new(start_ms: u64) -> Self {
        Self {
            start_ms,
            pause_state: PauseState::new(),
        }
    }

    pub fn target_time_ms(&self, interval_ms: u64) -> u64 {
        self.start_ms + interval_ms + self.pause_state.total_paused_ms
    }
}

// Tracks response state to avoid races between checking and setting the response.
pub struct ResponseState {
    pub waiting: bool,
    pub response: Option<bool>,
    pub pause_changed: bool,
}

impl ResponseState {
    pub fn new() -> Self {
        Self {
            waiting: false,
            response: None,
            pause_changed: false,
        }
    }

    // Returns true if the response was accepted (only accepted while waiting).
    pub fn try_respond(&mut self, was_working: bool) -> bool {
        if self.waiting {
            self.response = Some(was_working);
            true
        } else {
            false
        }
    }

    pub fn start_waiting(&mut self) {
        self.waiting = true;
        self.response = None;
    }

    pub fn stop_waiting(&mut self) {
        self.waiting = false;
    }

    pub fn is_waiting(&self) -> bool {
        self.waiting
    }

    pub fn take_response(&mut self) -> Option<bool> {
        self.response.take()
    }

    pub fn notify_pause_change(&mut self) {
        self.pause_changed = true;
    }

    pub fn clear_pause_flag(&mut self) {
        self.pause_changed = false;
    }
}

pub struct TimerState {
    pub running: Arc<AtomicBool>,
    pub session_state: Arc<Mutex<SessionState>>,
    pub response_state: Arc<Mutex<ResponseState>>,
    pub response_condvar: Arc<Condvar>,
    pub completed_count: Arc<AtomicU64>,
}

impl TimerState {
    pub fn new(start_ms: u64) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            session_state: Arc::new(Mutex::new(SessionState::new(start_ms))),
            response_state: Arc::new(Mutex::new(ResponseState::new())),
            response_condvar: Arc::new(Condvar::new()),
            completed_count: Arc::new(AtomicU64::new(0)),
        }
    }
}

fn socket_handler(listener: UnixListener, state: Arc<TimerState>, topic: String, interval_ms: u64) {
    while state.running.load(Ordering::Acquire) {
        let (mut stream, _) = match listener.accept() {
            Ok(conn) => conn,
            Err(_) => {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };

        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));

        let mut cmd_byte = [0u8; 1];
        if stream.read_exact(&mut cmd_byte).is_err() {
            continue;
        }

        let response = match cmd_byte[0] {
            CMD_STOP => {
                if let Ok(mut resp_state) = state.response_state.lock() {
                    resp_state.stop_waiting();
                }
                state.running.store(false, Ordering::Release);
                state.response_condvar.notify_all();
                vec![RESP_OK]
            }
            CMD_PAUSE => {
                if let Ok(mut session) = state.session_state.lock() {
                    if let Ok(mut resp) = state.response_state.lock() {
                        if resp.is_waiting() {
                            vec![RESP_ERROR]
                        } else {
                            session.pause_state.pause(now_ms());
                            resp.notify_pause_change();
                            drop(resp);
                            drop(session);
                            state.response_condvar.notify_all();
                            vec![RESP_OK]
                        }
                    } else {
                        vec![RESP_ERROR]
                    }
                } else {
                    vec![RESP_ERROR]
                }
            }
            CMD_RESUME => {
                if let Ok(mut session) = state.session_state.lock() {
                    if let Ok(mut resp) = state.response_state.lock() {
                        session.pause_state.resume(now_ms());
                        resp.notify_pause_change();
                        drop(resp);
                        drop(session);
                        state.response_condvar.notify_all();
                        vec![RESP_OK]
                    } else {
                        vec![RESP_ERROR]
                    }
                } else {
                    vec![RESP_ERROR]
                }
            }
            CMD_TOGGLE => {
                if let Ok(mut session) = state.session_state.lock() {
                    if let Ok(mut resp) = state.response_state.lock() {
                        if resp.is_waiting() {
                            vec![RESP_ERROR]
                        } else {
                            let now = now_ms();
                            if session.pause_state.is_paused() {
                                session.pause_state.resume(now);
                            } else {
                                session.pause_state.pause(now);
                            }
                            resp.notify_pause_change();
                            drop(resp);
                            drop(session);
                            state.response_condvar.notify_all();
                            vec![RESP_OK]
                        }
                    } else {
                        vec![RESP_ERROR]
                    }
                } else {
                    vec![RESP_ERROR]
                }
            }
            CMD_STATUS => {
                let session = state.session_state.lock().unwrap();
                let is_waiting = state
                    .response_state
                    .lock()
                    .map(|s| s.is_waiting())
                    .unwrap_or(false);

                let status_code = if is_waiting {
                    Status::Waiting
                } else if session.pause_state.is_paused() {
                    Status::Paused
                } else {
                    Status::Running
                };

                let response = StatusResponse {
                    topic: topic.clone(),
                    count: state.completed_count.load(Ordering::Acquire),
                    session_start_ms: session.start_ms,
                    interval_ms,
                    status: status_code.as_u8(),
                    paused_at_ms: session.pause_state.get_paused_at(),
                    total_paused_ms: session.pause_state.get_total_paused(),
                    pause_count: session.pause_state.get_pause_count(),
                };
                drop(session);

                let mut buf = [0u8; 512];
                let mut cursor = Cursor::new(&mut buf[..]);
                if response.write_to(&mut cursor).is_ok() {
                    let len = cursor.position() as usize;
                    buf[..len].to_vec()
                } else {
                    vec![RESP_ERROR]
                }
            }
            CMD_WORKING => {
                let accepted = state
                    .response_state
                    .lock()
                    .map(|mut s| s.try_respond(true))
                    .unwrap_or(false);

                if accepted {
                    state.response_condvar.notify_all();
                    vec![RESP_OK]
                } else {
                    vec![RESP_ERROR]
                }
            }
            CMD_WASTING => {
                let accepted = state
                    .response_state
                    .lock()
                    .map(|mut s| s.try_respond(false))
                    .unwrap_or(false);

                if accepted {
                    state.response_condvar.notify_all();
                    vec![RESP_OK]
                } else {
                    vec![RESP_ERROR]
                }
            }
            _ => vec![RESP_ERROR],
        };

        let _ = stream.write_all(&response);
        let _ = stream.shutdown(std::net::Shutdown::Write);
    }
}

fn play_beep(output_stream: &Option<Arc<OutputStream>>) {
    if let Some(stream) = output_stream {
        let cursor = Cursor::new(crate::get_audio_data());
        if let Ok(source) = Decoder::new(cursor) {
            let sink = Sink::connect_new(stream.mixer());
            sink.append(source);
            sink.sleep_until_end();
        }
    }
}

fn execute_timer_finish_script(
    script_path: Option<&PathBuf>,
    topic: &str,
    duration_secs: u64,
    session_count: u64,
) {
    let Some(script_path) = script_path else {
        return;
    };

    let topic = topic
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(256)
        .collect::<String>();

    let result = std::process::Command::new(script_path)
        .env("TASKBEEP_TOPIC", topic)
        .env("TASKBEEP_DURATION", duration_secs.to_string())
        .env("TASKBEEP_SESSION_COUNT", session_count.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    if let Err(e) = result {
        eprintln!(
            "Warning: Failed to execute timer finish script '{}': {}",
            script_path.display(),
            e
        );
    }
}

fn try_bind_socket() -> Result<UnixListener> {
    let sock_path = socket_path();

    if sock_path.exists() {
        match UnixStream::connect(&sock_path) {
            Ok(_) => {
                return Err(TaskBeepError::TimerError(
                    "Timer already running".to_string(),
                ));
            }
            Err(_) => {
                fs::remove_file(&sock_path)?;
            }
        }
    }

    Ok(UnixListener::bind(&sock_path)?)
}

pub fn run_daemon(topic: String, interval_ms: u64, response_timeout: Option<u64>) {
    let listener = match try_bind_socket() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to start daemon: {}", e);
            std::process::exit(1);
        }
    };

    listener.set_nonblocking(true).expect("set nonblocking");

    let state = Arc::new(TimerState::new(now_ms()));

    let config = crate::get_config();
    let timer_finish_script = config.on_timer_finish.as_ref().map(PathBuf::from);
    let response_timeout_secs = response_timeout
        .map(|t| if t == 0 { None } else { Some(t) })
        .unwrap_or(config.response_timeout_secs);

    {
        let running = state.running.clone();
        let response_condvar = state.response_condvar.clone();
        let _ = ctrlc::set_handler(move || {
            running.store(false, Ordering::Release);
            response_condvar.notify_all();
        });
    }

    {
        let state_clone = state.clone();
        let topic_clone = topic.clone();
        thread::spawn(move || {
            socket_handler(listener, state_clone, topic_clone, interval_ms);
        });
    }

    let audio_stream = match OutputStreamBuilder::open_default_stream() {
        Ok(stream) => Some(Arc::new(stream)),
        Err(e) => {
            eprintln!("Warning: No audio available: {}", e);
            None
        }
    };

    while state.running.load(Ordering::Acquire) {
        {
            let mut session = state.session_state.lock().unwrap();
            *session = SessionState::new(now_ms());
        }

        let _session_start = Instant::now();

        while state.running.load(Ordering::Acquire) {
            let now = now_ms();
            let session = state.session_state.lock().unwrap();

            if session.pause_state.is_paused() {
                drop(session);
                if let Ok(mut resp_state) = state.response_state.lock() {
                    resp_state.clear_pause_flag();
                    let _guard = state.response_condvar.wait(resp_state);
                }
                continue;
            }

            let target = session.target_time_ms(interval_ms);
            drop(session);

            if now >= target {
                break;
            }

            if let Ok(resp_state) = state.response_state.lock() {
                let remaining = target.saturating_sub(now);
                let wait_time = Duration::from_millis(remaining);
                let _ = state.response_condvar.wait_timeout(resp_state, wait_time);
            }
        }

        if !state.running.load(Ordering::Acquire) {
            break;
        }

        let beep_time = now_ms();
        play_beep(&audio_stream);

        let duration_secs = interval_ms / MILLIS_PER_SECOND;
        let current_count = state.completed_count.fetch_add(1, Ordering::AcqRel) + 1;
        execute_timer_finish_script(
            timer_finish_script.as_ref(),
            &topic,
            duration_secs,
            current_count,
        );

        if let Ok(mut resp_state) = state.response_state.lock() {
            resp_state.start_waiting();
        }

        let wait_start = Instant::now();
        let mut got_response = false;
        let timeout_ms = response_timeout_secs.map(|s| s * MILLIS_PER_SECOND);

        while state.running.load(Ordering::Acquire)
            && timeout_ms.is_none_or(|t| wait_start.elapsed().as_millis() < t as u128)
        {
            let (session_start, pause_count, pause_duration) = {
                let session = state.session_state.lock().unwrap();
                (
                    session.start_ms,
                    session.pause_state.get_pause_count(),
                    session.pause_state.get_total_paused(),
                )
            };

            if let Ok(mut resp_state) = state.response_state.lock() {
                if let Some(was_working) = resp_state.take_response() {
                    drop(resp_state);
                    let entry = StatsEntry {
                        start_time_ms: session_start,
                        end_time_ms: beep_time,
                        duration_ms: interval_ms,
                        pause_count,
                        pause_duration_ms: pause_duration,
                        topic: topic.clone(),
                        was_working,
                    };
                    let _ = append_stats(&entry);
                    got_response = true;
                    break;
                }

                let remaining_ms = timeout_ms
                    .map(|t| t.saturating_sub(wait_start.elapsed().as_millis() as u64))
                    .unwrap_or(MILLIS_PER_SECOND);
                if remaining_ms > 0 {
                    let wait_time = Duration::from_millis(remaining_ms.min(MILLIS_PER_SECOND));
                    let _ = state.response_condvar.wait_timeout(resp_state, wait_time);
                } else {
                    break;
                }
            }
        }

        if let Ok(mut resp_state) = state.response_state.lock() {
            resp_state.stop_waiting();
        }

        if !got_response && state.running.load(Ordering::Acquire) {
            let (session_start, pause_count, pause_duration) = {
                let session = state.session_state.lock().unwrap();
                (
                    session.start_ms,
                    session.pause_state.get_pause_count(),
                    session.pause_state.get_total_paused(),
                )
            };
            let entry = StatsEntry {
                start_time_ms: session_start,
                end_time_ms: beep_time,
                duration_ms: interval_ms,
                pause_count,
                pause_duration_ms: pause_duration,
                topic: topic.clone(),
                was_working: false,
            };
            let _ = append_stats(&entry);
            break;
        }
    }

    let _ = fs::remove_file(socket_path());
}

pub fn start_timer(topic: String, interval: u64, response_timeout: Option<u64>) -> Result<()> {
    let topic = validate_topic(&topic)?;
    let interval = validate_interval(interval)?;
    let interval_ms = interval * MILLIS_PER_SECOND;

    if crate::protocol::get_status().is_ok() {
        return Err(TaskBeepError::TimerError(
            "Timer already running. Stop it first.".to_string(),
        ));
    }

    println!("Starting timer: '{}' ({}s intervals)", topic, interval);

    let daemonize = Daemonize::new()
        .working_directory(get_runtime_dir())
        .umask(0o027);

    match daemonize.start() {
        Ok(_) => {
            run_daemon(topic, interval_ms, response_timeout);
            std::process::exit(0);
        }
        Err(e) => Err(TaskBeepError::TimerError(format!(
            "Failed to daemonize: {}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::StatsEntry;

    #[test]
    fn test_pause_state_new() {
        let pause = PauseState::new();
        assert!(!pause.is_paused());
        assert_eq!(pause.get_total_paused(), 0);
        assert_eq!(pause.get_paused_at(), 0);
    }

    #[test]
    fn test_pause_state_pause_resume() {
        let mut pause = PauseState::new();

        pause.pause(1000);
        assert!(pause.is_paused());
        assert_eq!(pause.get_paused_at(), 1000);

        pause.resume(2000);
        assert!(!pause.is_paused());
        assert_eq!(pause.get_total_paused(), 1000);

        pause.pause(3000);
        assert!(pause.is_paused());
        assert_eq!(pause.get_paused_at(), 3000);

        pause.resume(5000);
        assert!(!pause.is_paused());
        assert_eq!(pause.get_total_paused(), 3000);
    }

    #[test]
    fn test_session_state_new() {
        let session = SessionState::new(1000);
        assert_eq!(session.start_ms, 1000);
        assert!(!session.pause_state.is_paused());
    }

    #[test]
    fn test_response_state_new() {
        let state = ResponseState::new();
        assert!(!state.is_waiting());
        assert_eq!(state.response, None);
    }

    #[test]
    fn test_response_state_start_waiting() {
        let mut state = ResponseState::new();
        state.start_waiting();
        assert!(state.is_waiting());
        assert_eq!(state.response, None);
    }

    #[test]
    fn test_response_state_try_respond_when_waiting() {
        let mut state = ResponseState::new();
        state.start_waiting();
        assert!(state.try_respond(true));
        assert_eq!(state.response, Some(true));
        assert!(state.is_waiting());
    }

    #[test]
    fn test_response_state_try_respond_when_not_waiting() {
        let mut state = ResponseState::new();
        assert!(!state.try_respond(true));
        assert_eq!(state.response, None);
    }

    #[test]
    fn test_response_state_race_condition_prevented() {
        let mut state = ResponseState::new();
        state.start_waiting();
        assert!(state.try_respond(true));
        assert_eq!(state.response, Some(true));
        state.stop_waiting();
        assert!(!state.try_respond(false));
        assert_eq!(state.response, Some(true));
    }

    #[test]
    fn test_response_state_take_response() {
        let mut state = ResponseState::new();
        state.start_waiting();
        state.try_respond(false);
        assert_eq!(state.take_response(), Some(false));
        assert_eq!(state.take_response(), None);
    }

    #[test]
    fn test_response_state_start_waiting_clears_old_response() {
        let mut state = ResponseState::new();
        state.start_waiting();
        state.try_respond(true);
        assert_eq!(state.response, Some(true));
        state.start_waiting();
        assert_eq!(state.response, None);
        assert!(state.is_waiting());
    }

    #[test]
    fn test_response_state_atomicity() {
        let mut state = ResponseState::new();
        state.start_waiting();
        assert!(state.is_waiting());
        let accepted1 = state.try_respond(true);
        assert!(accepted1);
        state.stop_waiting();
        let accepted2 = state.try_respond(false);
        assert!(!accepted2);
        assert_eq!(state.response, Some(true));
    }

    // A second consecutive pause() must be a no-op.
    #[test]
    fn pause_double_pause_is_noop() {
        let mut ps = PauseState::new();
        ps.pause(1_000);
        ps.pause(5_000);
        assert_eq!(
            ps.get_paused_at(),
            1_000,
            "second pause must not overwrite first"
        );
        ps.resume(6_000);
        assert_eq!(ps.get_total_paused(), 5_000);
    }

    // resume() without a prior pause() must not corrupt total_paused_ms or pause_count.
    #[test]
    fn pause_resume_without_prior_pause_is_noop() {
        let mut ps = PauseState::new();
        ps.resume(5_000);
        assert!(!ps.is_paused());
        assert_eq!(ps.get_total_paused(), 0);
        assert_eq!(ps.get_pause_count(), 0);
    }

    // Pause duration must accumulate correctly across multiple pause/resume cycles.
    #[test]
    fn pause_multiple_cycles_accumulate_correctly() {
        let mut ps = PauseState::new();
        ps.pause(0);
        ps.resume(3_000);
        ps.pause(10_000);
        ps.resume(17_000);
        ps.pause(20_000);
        ps.resume(21_500);
        assert_eq!(ps.get_total_paused(), 11_500);
        assert_eq!(ps.get_pause_count(), 3);
    }

    // total_paused_ms must not include the in-progress pause until resume() is called.
    #[test]
    fn pause_ongoing_pause_not_counted_in_total_until_resumed() {
        let mut ps = PauseState::new();
        ps.pause(10_000);
        assert_eq!(ps.get_total_paused(), 0);
        ps.resume(15_000);
        assert_eq!(ps.get_total_paused(), 5_000);
    }

    // Target time must be extended by the exact pause duration.
    #[test]
    fn session_target_time_extends_by_pause_duration() {
        let interval_ms: u64 = 60_000;
        let mut session = SessionState::new(0);

        session.pause_state.pause(20_000);
        session.pause_state.resume(30_000);

        assert_eq!(session.target_time_ms(interval_ms), 70_000);
        assert!(
            65_000 < session.target_time_ms(interval_ms),
            "timer must not expire at 65 s when 10 s was paused"
        );
    }

    // With no pauses the target time is simply start + interval.
    #[test]
    fn session_target_time_no_pause_equals_start_plus_interval() {
        let session = SessionState::new(5_000);
        assert_eq!(session.target_time_ms(30_000), 35_000);
    }

    // pause_duration_ms must only reflect time paused during the interval, not response-wait time.
    #[test]
    fn logged_pause_duration_reflects_only_paused_time() {
        let mut ps = PauseState::new();
        ps.pause(10_000);
        ps.resume(17_000);
        let pause_duration_at_beep = ps.get_total_paused();
        let pause_count_at_beep = ps.get_pause_count();

        let entry = StatsEntry {
            start_time_ms: 0,
            end_time_ms: 67_000,
            duration_ms: 60_000,
            pause_count: pause_count_at_beep,
            pause_duration_ms: pause_duration_at_beep,
            topic: "work".to_string(),
            was_working: true,
        };

        assert_eq!(entry.pause_duration_ms, 7_000);
        assert_eq!(entry.pause_count, 1);
    }

    // Full invariant: target time, end_time_ms, duration_ms and pause_duration_ms must be consistent.
    #[test]
    fn session_and_log_invariants_are_consistent_after_pause() {
        let interval_ms: u64 = 60_000;
        let start_ms: u64 = 1_000_000;
        let mut session = SessionState::new(start_ms);

        session.pause_state.pause(start_ms + 20_000);
        session.pause_state.resume(start_ms + 25_000);

        let expected_beep_time = session.target_time_ms(interval_ms);
        assert_eq!(expected_beep_time, 1_065_000);

        let entry = StatsEntry {
            start_time_ms: session.start_ms,
            end_time_ms: expected_beep_time,
            duration_ms: interval_ms,
            pause_count: session.pause_state.get_pause_count(),
            pause_duration_ms: session.pause_state.get_total_paused(),
            topic: "work".to_string(),
            was_working: true,
        };

        assert_eq!(
            entry.end_time_ms - entry.start_time_ms,
            entry.duration_ms + entry.pause_duration_ms
        );
        assert_eq!(entry.duration_ms, interval_ms);
        assert_eq!(entry.pause_duration_ms, 5_000);
    }
}
