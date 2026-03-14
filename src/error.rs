use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TaskBeepError {
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

pub type Result<T> = std::result::Result<T, TaskBeepError>;
