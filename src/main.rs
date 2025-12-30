mod audio;

use clap::{Parser, Subcommand};
use daemonize::Daemonize;
use rodio::{Decoder, OutputStream, OutputStreamBuilder, Sink};
use serde_json::json;
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Cursor, Read, Write},
    os::unix::{
        fs::OpenOptionsExt,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

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
    /// Start a Pomodoro timer with a topic and interval in seconds (default 1500s/25min)
    Start {
        /// The topic/task you're working on
        topic: String,
        /// Interval in seconds (default 1500s/25 minutes)
        #[arg(default_value_t = 1500)]
        interval: u64,
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
    /// Clear all stored statistics (requires confirmation)
    Clear {
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

// Time constants
const MILLIS_PER_SECOND: u64 = 1000;
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3600;
const SECONDS_PER_DAY: u64 = 86400;

const SOCKET_NAME: &str = "taskbeep.sock";
const STATS_FILE_NAME: &str = ".taskbeep.stats";
const MIN_INTERVAL_SECS: u64 = 1;
const MAX_INTERVAL_SECS: u64 = SECONDS_PER_DAY; // 24 hours
const MAX_TOPIC_LEN: usize = 255;
const RESPONSE_TIMEOUT_MS: u64 = 300_000; // 5 minutes
const STATS_VERSION: u8 = 1;

static AUDIO_DATA: OnceLock<Vec<u8>> = OnceLock::new();

fn get_audio_data() -> &'static [u8] {
    AUDIO_DATA.get_or_init(audio::generate_beep_audio)
}

// Protocol commands
const CMD_STOP: u8 = 0x01;
const CMD_PAUSE: u8 = 0x02;
const CMD_RESUME: u8 = 0x03;
const CMD_TOGGLE: u8 = 0x04;
const CMD_STATUS: u8 = 0x05;
const CMD_WORKING: u8 = 0x06;
const CMD_WASTING: u8 = 0x07;

// Response codes
const RESP_OK: u8 = 0x00;
const RESP_ERROR: u8 = 0xFF;

// Status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Status {
    Running = 0x01,
    Paused = 0x02,
    Waiting = 0x03,
}

impl Status {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Status::Running),
            0x02 => Some(Status::Paused),
            0x03 => Some(Status::Waiting),
            _ => None,
        }
    }

    fn as_u8(self) -> u8 {
        self as u8
    }
}

// Define custom error type
#[derive(Error, Debug)]
enum TaskBeepError {
    #[error("Timer error: {0}")]
    TimerError(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Socket error: {0}")]
    SocketError(String),

    #[error("Stats error: {0}")]
    StatsError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("{0}")]
    Generic(String),
}

// Allow conversion from String for backwards compatibility
impl From<String> for TaskBeepError {
    fn from(s: String) -> Self {
        TaskBeepError::Generic(s)
    }
}

impl From<&str> for TaskBeepError {
    fn from(s: &str) -> Self {
        TaskBeepError::Generic(s.to_string())
    }
}

impl From<std::array::TryFromSliceError> for TaskBeepError {
    fn from(e: std::array::TryFromSliceError) -> Self {
        TaskBeepError::ParseError(e.to_string())
    }
}

type Result<T> = std::result::Result<T, TaskBeepError>;

// Properly aligned status response (no packed UB)
#[derive(Debug, Clone)]
struct StatusResponse {
    topic: String,
    count: u64,
    session_start_ms: u64,
    interval_ms: u64,
    status: u8,
    paused_at_ms: u64,
    total_paused_ms: u64,
}

impl StatusResponse {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let topic_bytes = self.topic.as_bytes();
        let topic_len = topic_bytes.len().min(255) as u8;

        writer.write_all(&[topic_len])?;
        writer.write_all(&topic_bytes[..topic_len as usize])?;
        writer.write_all(&self.count.to_le_bytes())?;
        writer.write_all(&self.session_start_ms.to_le_bytes())?;
        writer.write_all(&self.interval_ms.to_le_bytes())?;
        writer.write_all(&[self.status])?;
        writer.write_all(&self.paused_at_ms.to_le_bytes())?;
        writer.write_all(&self.total_paused_ms.to_le_bytes())?;
        Ok(())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(TaskBeepError::SocketError("Empty response".to_string()));
        }

        let topic_len = bytes[0] as usize;
        if bytes.len() < 1 + topic_len + 8 * 5 + 1 {
            return Err(TaskBeepError::SocketError("Response too short".to_string()));
        }
        let topic = String::from_utf8_lossy(&bytes[1..1 + topic_len]).to_string();
        let mut pos = 1 + topic_len;

        let count = u64::from_le_bytes(bytes[pos..pos + 8].try_into()?);
        pos += 8;
        let session_start_ms = u64::from_le_bytes(bytes[pos..pos + 8].try_into()?);
        pos += 8;
        let interval_ms = u64::from_le_bytes(bytes[pos..pos + 8].try_into()?);
        pos += 8;
        let status = bytes[pos];
        pos += 1;
        let paused_at_ms = u64::from_le_bytes(bytes[pos..pos + 8].try_into()?);
        pos += 8;
        let total_paused_ms = u64::from_le_bytes(bytes[pos..pos + 8].try_into()?);

        Ok(StatusResponse {
            topic,
            count,
            session_start_ms,
            interval_ms,
            status,
            paused_at_ms,
            total_paused_ms,
        })
    }
}

#[derive(Debug, Clone)]
struct StatsEntry {
    start_time_ms: u64,
    end_time_ms: u64,
    topic: String,
    was_working: bool,
}

impl StatsEntry {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(
            writer,
            "{}\t{}\t{}\t{}\t{}",
            STATS_VERSION,
            self.start_time_ms,
            self.end_time_ms,
            self.topic.replace(&['\t', '\n', '\r'][..], " "),
            if self.was_working {
                "working"
            } else {
                "wasting"
            }
        )
    }

    fn from_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 5 {
            return None;
        }

        let version: u8 = parts[0].parse().ok()?;
        if version != STATS_VERSION {
            return None;
        }

        Some(StatsEntry {
            start_time_ms: parts[1].parse().ok()?,
            end_time_ms: parts[2].parse().ok()?,
            topic: parts[3].to_string(),
            was_working: parts[4] == "working",
        })
    }

    fn duration_ms(&self) -> u64 {
        self.end_time_ms.saturating_sub(self.start_time_ms)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before UNIX epoch")
        .as_millis() as u64
}

struct DurationDisplay(u64);

impl std::fmt::Display for DurationDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let secs = self.0 / MILLIS_PER_SECOND;
        if secs == 0 {
            return write!(f, "0s");
        }

        let h = secs / SECONDS_PER_HOUR;
        let m = (secs % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
        let s = secs % SECONDS_PER_MINUTE;

        let mut first = true;

        if h > 0 {
            write!(f, "{}h", h)?;
            first = false;
        }
        if m > 0 {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "{}m", m)?;
            first = false;
        }
        if s > 0 || first {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "{}s", s)?;
        }

        Ok(())
    }
}

#[cfg(test)]
fn format_duration(ms: u64) -> String {
    DurationDisplay(ms).to_string()
}

fn get_runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn socket_path() -> PathBuf {
    get_runtime_dir().join(SOCKET_NAME)
}

fn statsfile_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(STATS_FILE_NAME)
    } else {
        get_runtime_dir().join(STATS_FILE_NAME)
    }
}

fn validate_topic(topic: &str) -> Result<String> {
    if topic.is_empty() {
        return Err(TaskBeepError::ConfigError(
            "Topic cannot be empty".to_string(),
        ));
    }
    if topic.len() > MAX_TOPIC_LEN {
        return Err(TaskBeepError::ConfigError(format!(
            "Topic too long (max {} characters)",
            MAX_TOPIC_LEN
        )));
    }
    if topic.contains(&['\0', '\n', '\r', '\t'][..]) {
        return Err(TaskBeepError::ConfigError(
            "Topic contains invalid characters".to_string(),
        ));
    }
    Ok(topic.to_string())
}

fn validate_interval(interval: u64) -> Result<u64> {
    if interval < MIN_INTERVAL_SECS {
        return Err(TaskBeepError::ConfigError(format!(
            "Interval too short (min {}s)",
            MIN_INTERVAL_SECS
        )));
    }
    if interval > MAX_INTERVAL_SECS {
        return Err(TaskBeepError::ConfigError(format!(
            "Interval too long (max {}s)",
            MAX_INTERVAL_SECS
        )));
    }
    Ok(interval)
}

fn send_command(cmd: u8) -> Result<Vec<u8>> {
    let sock_path = socket_path();
    if !sock_path.exists() {
        return Err(TaskBeepError::TimerError("Timer not running".to_string()));
    }

    let mut stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(e) => {
            // Socket file exists but connection failed - likely stale socket
            if e.kind() == io::ErrorKind::ConnectionRefused {
                // Clean up stale socket
                let _ = fs::remove_file(&sock_path);
                return Err(TaskBeepError::TimerError("Timer not running".to_string()));
            }
            return Err(e.into());
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    stream.write_all(&[cmd])?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    Ok(response)
}

fn get_status() -> Result<StatusResponse> {
    let response = send_command(CMD_STATUS)?;
    StatusResponse::from_bytes(&response)
}

fn append_stats(entry: &StatsEntry) -> Result<()> {
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

struct PauseState {
    paused_at_ms: Option<u64>,
    total_paused_ms: u64,
}

impl PauseState {
    fn new() -> Self {
        Self {
            paused_at_ms: None,
            total_paused_ms: 0,
        }
    }

    fn is_paused(&self) -> bool {
        self.paused_at_ms.is_some()
    }

    fn pause(&mut self, now: u64) {
        if self.paused_at_ms.is_none() {
            self.paused_at_ms = Some(now);
        }
    }

    fn resume(&mut self, now: u64) {
        if let Some(paused_at) = self.paused_at_ms {
            self.total_paused_ms += now.saturating_sub(paused_at);
            self.paused_at_ms = None;
        }
    }

    fn get_paused_at(&self) -> u64 {
        self.paused_at_ms.unwrap_or(0)
    }

    fn get_total_paused(&self) -> u64 {
        self.total_paused_ms
    }
}

struct SessionState {
    start_ms: u64,
    pause_state: PauseState,
}

impl SessionState {
    fn new(start_ms: u64) -> Self {
        Self {
            start_ms,
            pause_state: PauseState::new(),
        }
    }

    fn target_time_ms(&self, interval_ms: u64) -> u64 {
        self.start_ms + interval_ms + self.pause_state.total_paused_ms
    }
}

/// Tracks the response state atomically to avoid race conditions
/// between checking if waiting and setting the response
struct ResponseState {
    waiting: bool,
    response: Option<bool>,
    pause_changed: bool,
}

impl ResponseState {
    fn new() -> Self {
        Self {
            waiting: false,
            response: None,
            pause_changed: false,
        }
    }

    /// Attempt to set response if currently waiting
    /// Returns true if response was accepted, false otherwise
    fn try_respond(&mut self, was_working: bool) -> bool {
        if self.waiting {
            self.response = Some(was_working);
            true
        } else {
            false
        }
    }

    fn start_waiting(&mut self) {
        self.waiting = true;
        self.response = None;
    }

    fn stop_waiting(&mut self) {
        self.waiting = false;
    }

    fn is_waiting(&self) -> bool {
        self.waiting
    }

    fn take_response(&mut self) -> Option<bool> {
        self.response.take()
    }

    fn notify_pause_change(&mut self) {
        self.pause_changed = true;
    }

    fn clear_pause_flag(&mut self) {
        self.pause_changed = false;
    }
}

struct TimerState {
    running: Arc<AtomicBool>,
    session_state: Arc<Mutex<SessionState>>,
    response_state: Arc<Mutex<ResponseState>>,
    response_condvar: Arc<Condvar>,
    completed_count: Arc<AtomicU64>,
}

impl TimerState {
    fn new(start_ms: u64) -> Self {
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
                state.running.store(false, Ordering::Release);
                vec![RESP_OK]
            }
            CMD_PAUSE => {
                let is_waiting = state
                    .response_state
                    .lock()
                    .map(|s| s.is_waiting())
                    .unwrap_or(false);

                if is_waiting {
                    vec![RESP_ERROR]
                } else if let Ok(mut session) = state.session_state.lock() {
                    session.pause_state.pause(now_ms());
                    // Hold session lock while acquiring response lock to maintain consistent ordering
                    if let Ok(mut resp) = state.response_state.lock() {
                        resp.notify_pause_change();
                        drop(resp);
                    }
                    drop(session);
                    state.response_condvar.notify_all();
                    vec![RESP_OK]
                } else {
                    vec![RESP_ERROR]
                }
            }
            CMD_RESUME => {
                if let Ok(mut session) = state.session_state.lock() {
                    session.pause_state.resume(now_ms());
                    // Hold session lock while acquiring response lock to maintain consistent ordering
                    if let Ok(mut resp) = state.response_state.lock() {
                        resp.notify_pause_change();
                        drop(resp);
                    }
                    drop(session);
                    state.response_condvar.notify_all();
                    vec![RESP_OK]
                } else {
                    vec![RESP_ERROR]
                }
            }
            CMD_TOGGLE => {
                if let Ok(mut session) = state.session_state.lock() {
                    let now = now_ms();
                    if session.pause_state.is_paused() {
                        session.pause_state.resume(now);
                    } else {
                        session.pause_state.pause(now);
                    }
                    // Hold session lock while acquiring response lock to maintain consistent ordering
                    if let Ok(mut resp) = state.response_state.lock() {
                        resp.notify_pause_change();
                        drop(resp);
                    }
                    drop(session);
                    state.response_condvar.notify_all();
                    vec![RESP_OK]
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
        let cursor = Cursor::new(get_audio_data());
        if let Ok(source) = Decoder::new(cursor) {
            let sink = Sink::connect_new(stream.mixer());
            sink.append(source);
            sink.sleep_until_end();
        }
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

fn run_daemon(topic: String, interval_ms: u64) {
    let listener = match try_bind_socket() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to start daemon: {}", e);
            std::process::exit(1);
        }
    };

    listener.set_nonblocking(true).expect("set nonblocking");

    let state = Arc::new(TimerState::new(now_ms()));

    // Setup signal handler
    {
        let running = state.running.clone();
        let _ = ctrlc::set_handler(move || {
            running.store(false, Ordering::Release);
        });
    }

    // Start socket handler thread
    {
        let state_clone = state.clone();
        let topic_clone = topic.clone();
        thread::spawn(move || {
            socket_handler(listener, state_clone, topic_clone, interval_ms);
        });
    }

    // Setup audio
    let audio_stream = match OutputStreamBuilder::open_default_stream() {
        Ok(stream) => Some(Arc::new(stream)),
        Err(e) => {
            eprintln!("Warning: No audio available: {}", e);
            None
        }
    };

    while state.running.load(Ordering::Acquire) {
        // Reset session start for new interval
        {
            let mut session = state.session_state.lock().unwrap();
            *session = SessionState::new(now_ms());
        }

        // Wait for interval to complete
        let _session_start = Instant::now();
        let mut early_response = false;

        while state.running.load(Ordering::Acquire) {
            let now = now_ms();
            let session = state.session_state.lock().unwrap();

            // Check if paused - wait on condvar indefinitely until resume
            if session.pause_state.is_paused() {
                drop(session);
                if let Ok(mut resp_state) = state.response_state.lock() {
                    resp_state.clear_pause_flag();
                    // Wait indefinitely until notified (resume/stop)
                    let _guard = state.response_condvar.wait(resp_state);
                }
                continue;
            }

            // Check for early response (before timer completes)
            // Extract session data before acquiring response_state lock to maintain consistent lock ordering
            let session_start = session.start_ms;
            let target = session.target_time_ms(interval_ms);
            drop(session);

            if let Ok(mut resp_state) = state.response_state.lock()
                && let Some(was_working) = resp_state.take_response()
            {
                drop(resp_state);
                let entry = StatsEntry {
                    start_time_ms: session_start,
                    end_time_ms: now,
                    topic: topic.clone(),
                    was_working,
                };
                let _ = append_stats(&entry);
                state.completed_count.fetch_add(1, Ordering::Release);
                early_response = true;
                break;
            }

            // Check if interval completed

            if now >= target {
                break;
            }

            // Wait efficiently using condvar with timeout
            if let Ok(resp_state) = state.response_state.lock() {
                let remaining = target.saturating_sub(now);
                // Wait for full remaining time or until notified
                let wait_time = Duration::from_millis(remaining);
                let _ = state.response_condvar.wait_timeout(resp_state, wait_time);
            }
        }

        if early_response {
            continue;
        }

        if !state.running.load(Ordering::Acquire) {
            break;
        }

        // Play beep and wait for response
        play_beep(&audio_stream);
        if let Ok(mut resp_state) = state.response_state.lock() {
            resp_state.start_waiting();
        }

        let wait_start = Instant::now();
        let mut got_response = false;

        while state.running.load(Ordering::Acquire)
            && wait_start.elapsed().as_millis() < RESPONSE_TIMEOUT_MS as u128
        {
            // Acquire session lock first to extract data, maintaining consistent lock ordering
            let session_start = {
                let session = state.session_state.lock().unwrap();
                session.start_ms
            };

            if let Ok(mut resp_state) = state.response_state.lock() {
                if let Some(was_working) = resp_state.take_response() {
                    drop(resp_state);
                    let entry = StatsEntry {
                        start_time_ms: session_start,
                        end_time_ms: now_ms(),
                        topic: topic.clone(),
                        was_working,
                    };
                    let _ = append_stats(&entry);
                    state.completed_count.fetch_add(1, Ordering::Release);
                    got_response = true;
                    break;
                }

                // Wait efficiently using condvar
                let remaining_ms =
                    RESPONSE_TIMEOUT_MS.saturating_sub(wait_start.elapsed().as_millis() as u64);
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

        // Timeout: record as wasting and stop
        // Acquire session lock first to maintain consistent lock ordering
        if !got_response && state.running.load(Ordering::Acquire) {
            let session_start = {
                let session = state.session_state.lock().unwrap();
                session.start_ms
            };
            let entry = StatsEntry {
                start_time_ms: session_start,
                end_time_ms: now_ms(),
                topic: topic.clone(),
                was_working: false,
            };
            let _ = append_stats(&entry);
            state.completed_count.fetch_add(1, Ordering::Release);
            break;
        }
    }

    // Cleanup
    let _ = fs::remove_file(socket_path());
}

fn start_timer(topic: String, interval: u64) -> Result<()> {
    let topic = validate_topic(&topic)?;
    let interval = validate_interval(interval)?;
    let interval_ms = interval * MILLIS_PER_SECOND;

    if get_status().is_ok() {
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
            run_daemon(topic, interval_ms);
            std::process::exit(0);
        }
        Err(e) => Err(TaskBeepError::TimerError(format!(
            "Failed to daemonize: {}",
            e
        ))),
    }
}

fn stop_timer(working: bool, wasting: bool) -> Result<()> {
    // Get state before stopping
    let status = get_status()?;
    let status_enum = Status::from_u8(status.status).unwrap_or(Status::Running);

    // Calculate partial session if applicable
    if status_enum != Status::Waiting {
        let now = now_ms();
        let elapsed_active = if status_enum == Status::Paused {
            status
                .paused_at_ms
                .saturating_sub(status.session_start_ms)
                .saturating_sub(status.total_paused_ms)
        } else {
            now.saturating_sub(status.session_start_ms)
                .saturating_sub(status.total_paused_ms)
        };

        if elapsed_active > MILLIS_PER_SECOND && (working || wasting) {
            let entry = StatsEntry {
                start_time_ms: status.session_start_ms,
                end_time_ms: if status_enum == Status::Paused {
                    status.paused_at_ms
                } else {
                    now
                },
                topic: status.topic,
                was_working: working,
            };
            append_stats(&entry)?;
        }
    }

    // Send stop command
    let response = send_command(CMD_STOP)?;
    if response.first() == Some(&RESP_OK) {
        println!("Timer stopped");
        thread::sleep(Duration::from_millis(100));
        Ok(())
    } else {
        Err(TaskBeepError::TimerError(
            "Failed to stop timer".to_string(),
        ))
    }
}

fn show_status(format: &str) -> Result<()> {
    let status = get_status()?;
    let now = now_ms();

    let status_enum = Status::from_u8(status.status).unwrap_or(Status::Running);
    let status_str = match status_enum {
        Status::Paused => "paused",
        Status::Waiting => "waiting",
        Status::Running => "running",
    };

    let remaining = if status_enum == Status::Paused {
        status.session_start_ms + status.interval_ms + status.total_paused_ms - status.paused_at_ms
    } else {
        let target = status.session_start_ms + status.interval_ms + status.total_paused_ms;
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
            // Escape newlines, carriage returns, and equals signs in topic for safe parsing
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

fn send_signal(is_working: bool) -> Result<()> {
    let cmd = if is_working { CMD_WORKING } else { CMD_WASTING };
    let response = send_command(cmd)?;

    if response.first() == Some(&RESP_OK) {
        println!(
            "Recorded: {}",
            if is_working { "working" } else { "wasting" }
        );
        Ok(())
    } else {
        Err(TaskBeepError::TimerError(
            "Timer is not waiting for response".to_string(),
        ))
    }
}

fn pause_resume_toggle(cmd: u8, action: &str) -> Result<()> {
    let response = send_command(cmd)?;
    if response.first() == Some(&RESP_OK) {
        println!("Timer {}", action);
        Ok(())
    } else {
        Err(TaskBeepError::TimerError(format!(
            "Failed to {} timer",
            action
        )))
    }
}

fn get_period_start_ms(period: &str) -> Option<u64> {
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
fn show_stats(filter: Option<&str>) -> Result<()> {
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
    let mut topic_stats: HashMap<String, (u64, u64)> = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        if let Some(entry) = StatsEntry::from_line(&line) {
            if let Some(start) = filter_start
                && entry.start_time_ms < start
            {
                continue;
            }

            let duration = entry.duration_ms();
            let stats = topic_stats.entry(entry.topic.clone()).or_insert((0, 0));

            if entry.was_working {
                total_working_ms += duration;
                stats.0 += duration;
            } else {
                total_wasting_ms += duration;
                stats.1 += duration;
            }
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

    println!("\n=== By Topic ===");
    let mut topics: Vec<_> = topic_stats.iter().collect();
    topics.sort_by_key(|(_, (w, wa))| std::cmp::Reverse(w + wa));

    for (topic, (working, wasting)) in topics {
        let total = working + wasting;
        let prod = (*working as f64 / total as f64) * 100.0;
        println!(
            "{}: {} ({:.1}% productive)",
            topic,
            DurationDisplay(total),
            prod
        );
    }

    Ok(())
}

fn export_stats(output: PathBuf) -> Result<()> {
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

fn clear_stats(skip_confirmation: bool) -> Result<()> {
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

    if !skip_confirmation {
        print!("Delete all statistics? This cannot be undone. (y/N): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Cancelled");
            return Ok(());
        }
    }

    fs::remove_file(&stats_path)?;
    println!("Statistics cleared");
    Ok(())
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Start { topic, interval } => start_timer(topic, interval),
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
        Commands::Clear { yes } => clear_stats(yes),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_enum_conversion() {
        assert_eq!(Status::Running.as_u8(), 0x01);
        assert_eq!(Status::Paused.as_u8(), 0x02);
        assert_eq!(Status::Waiting.as_u8(), 0x03);

        assert_eq!(Status::from_u8(0x01), Some(Status::Running));
        assert_eq!(Status::from_u8(0x02), Some(Status::Paused));
        assert_eq!(Status::from_u8(0x03), Some(Status::Waiting));
        assert_eq!(Status::from_u8(0xFF), None);
    }

    #[test]
    fn test_status_enum_equality() {
        assert_eq!(Status::Running, Status::Running);
        assert_ne!(Status::Running, Status::Paused);
        assert_ne!(Status::Paused, Status::Waiting);
    }

    #[test]
    fn test_format_duration_zero() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(500), "0s");
        assert_eq!(format_duration(999), "0s");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(1_000), "1s");
        assert_eq!(format_duration(5_000), "5s");
        assert_eq!(format_duration(59_000), "59s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(60_000), "1m");
        assert_eq!(format_duration(120_000), "2m");
        assert_eq!(format_duration(90_000), "1m 30s");
        assert_eq!(format_duration(1_500_000), "25m");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3_600_000), "1h");
        assert_eq!(format_duration(7_200_000), "2h");
        assert_eq!(format_duration(3_660_000), "1h 1m");
        assert_eq!(format_duration(3_661_000), "1h 1m 1s");
    }

    #[test]
    fn test_format_duration_complex() {
        assert_eq!(format_duration(3_723_000), "1h 2m 3s");
        assert_eq!(format_duration(7_384_000), "2h 3m 4s");
        assert_eq!(format_duration(86_400_000), "24h");
    }

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
    fn test_stats_entry_serialization() {
        let entry = StatsEntry {
            start_time_ms: 1000,
            end_time_ms: 2000,
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
        assert_eq!(deserialized.topic, entry.topic);
        assert_eq!(deserialized.was_working, entry.was_working);
    }

    #[test]
    fn test_stats_entry_deserialization_invalid() {
        assert!(StatsEntry::from_line("1\t1000\t2000").is_none());
        assert!(StatsEntry::from_line("99\t1000\t2000\ttopic\tworking").is_none());
        assert!(StatsEntry::from_line("1\tabc\t2000\ttopic\tworking").is_none());
    }

    #[test]
    fn test_stats_entry_duration() {
        let entry = StatsEntry {
            start_time_ms: 1000,
            end_time_ms: 3500,
            topic: "test".to_string(),
            was_working: true,
        };
        assert_eq!(entry.duration_ms(), 2500);
    }

    #[test]
    fn test_status_response_serialization() {
        let response = StatusResponse {
            topic: "coding".to_string(),
            count: 5,
            session_start_ms: 1000,
            interval_ms: 1500000,
            status: Status::Running.as_u8(),
            paused_at_ms: 0,
            total_paused_ms: 0,
        };

        let mut buf = Vec::new();
        response.write_to(&mut buf).unwrap();
        let deserialized = StatusResponse::from_bytes(&buf).unwrap();

        assert_eq!(deserialized.topic, response.topic);
        assert_eq!(deserialized.count, response.count);
        assert_eq!(deserialized.session_start_ms, response.session_start_ms);
        assert_eq!(deserialized.interval_ms, response.interval_ms);
        assert_eq!(deserialized.status, response.status);
    }

    #[test]
    fn test_status_response_deserialization_invalid() {
        assert!(StatusResponse::from_bytes(&[]).is_err());
        assert!(StatusResponse::from_bytes(&[5u8, b't', b'e', b's', b't']).is_err());
    }

    #[test]
    fn test_calculate_total_duration() {
        let entries = [
            StatsEntry {
                start_time_ms: 0,
                end_time_ms: 60_000,
                topic: "task1".to_string(),
                was_working: true,
            },
            StatsEntry {
                start_time_ms: 60_000,
                end_time_ms: 120_000,
                topic: "task2".to_string(),
                was_working: true,
            },
        ];

        let total = entries
            .iter()
            .map(|e| e.end_time_ms - e.start_time_ms)
            .sum::<u64>();
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
                topic: "old".to_string(),
                was_working: true,
            },
            StatsEntry {
                start_time_ms: one_day_ago,
                end_time_ms: one_day_ago + 1000,
                topic: "recent".to_string(),
                was_working: true,
            },
            StatsEntry {
                start_time_ms: now - 1000,
                end_time_ms: now,
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

    #[test]
    fn test_now_ms() {
        let now = now_ms();
        assert!(now > 0);
        let year_2020_ms = 1577836800000u64;
        assert!(now > year_2020_ms);
    }

    #[test]
    fn test_format_duration_no_allocations() {
        let result = format_duration(3_723_000);
        assert_eq!(result, "1h 2m 3s");
        format_duration(0);
        format_duration(1);
        format_duration(u64::MAX / 2);
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
}
