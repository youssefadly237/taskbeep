use std::{
    fs,
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

use crate::error::{Result, TaskBeepError};
use crate::utils::socket_path;

// Commands sent from client to daemon
pub const CMD_STOP: u8 = 0x01;
pub const CMD_PAUSE: u8 = 0x02;
pub const CMD_RESUME: u8 = 0x03;
pub const CMD_TOGGLE: u8 = 0x04;
pub const CMD_STATUS: u8 = 0x05;
pub const CMD_WORKING: u8 = 0x06;
pub const CMD_WASTING: u8 = 0x07;

// Response codes sent from daemon back to client
pub const RESP_OK: u8 = 0x00;
pub const RESP_ERROR: u8 = 0xFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Running = 0x01,
    Paused = 0x02,
    Waiting = 0x03,
}

impl Status {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Status::Running),
            0x02 => Some(Status::Paused),
            0x03 => Some(Status::Waiting),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone)]
pub struct StatusResponse {
    pub topic: String,
    pub count: u64,
    pub session_start_ms: u64,
    pub interval_ms: u64,
    pub status: u8,
    pub paused_at_ms: u64,
    pub total_paused_ms: u64,
    pub pause_count: u64,
}

impl StatusResponse {
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
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
        writer.write_all(&self.pause_count.to_le_bytes())?;
        Ok(())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(TaskBeepError::SocketError("Empty response".to_string()));
        }

        let topic_len = bytes[0] as usize;
        if bytes.len() < 1 + topic_len + 8 * 6 + 1 {
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
        pos += 8;
        let pause_count = u64::from_le_bytes(bytes[pos..pos + 8].try_into()?);

        Ok(StatusResponse {
            topic,
            count,
            session_start_ms,
            interval_ms,
            status,
            paused_at_ms,
            total_paused_ms,
            pause_count,
        })
    }
}

pub fn send_command(cmd: u8) -> Result<Vec<u8>> {
    let sock_path = socket_path();
    if !sock_path.exists() {
        return Err(TaskBeepError::TimerError("Timer not running".to_string()));
    }

    let mut stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(e) => {
            if e.kind() == io::ErrorKind::ConnectionRefused {
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

pub fn get_status() -> Result<StatusResponse> {
    let response = send_command(CMD_STATUS)?;
    StatusResponse::from_bytes(&response)
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
    fn test_status_response_serialization() {
        let response = StatusResponse {
            topic: "coding".to_string(),
            count: 5,
            session_start_ms: 1000,
            interval_ms: 1500000,
            status: Status::Running.as_u8(),
            paused_at_ms: 0,
            total_paused_ms: 0,
            pause_count: 3,
        };

        let mut buf = Vec::new();
        response.write_to(&mut buf).unwrap();
        let deserialized = StatusResponse::from_bytes(&buf).unwrap();

        assert_eq!(deserialized.topic, response.topic);
        assert_eq!(deserialized.count, response.count);
        assert_eq!(deserialized.session_start_ms, response.session_start_ms);
        assert_eq!(deserialized.interval_ms, response.interval_ms);
        assert_eq!(deserialized.status, response.status);
        assert_eq!(deserialized.pause_count, response.pause_count);
    }

    #[test]
    fn test_status_response_deserialization_invalid() {
        assert!(StatusResponse::from_bytes(&[]).is_err());
        assert!(StatusResponse::from_bytes(&[5u8, b't', b'e', b's', b't']).is_err());
    }
}
