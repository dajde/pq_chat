//! Error handling for the server.

use serde::{Deserialize, Serialize};

impl From<oqs::Error> for ServerError {
    fn from(error: oqs::Error) -> Self {
        ServerError::unknown(&format!("OQS error: {}", error))
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ServerError {
    fn from(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        ServerError::unknown(&format!("Error: {}", error))
    }
}

impl From<std::io::Error> for ServerError {
    fn from(error: std::io::Error) -> Self {
        ServerError::unknown(&format!("Error: {}", error))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ServerErrorKind {
    InvalidSignature,
    UsernameTaken,
    TimestampFailure,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerError {
    pub kind: ServerErrorKind,
    pub message: String,
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Server Error: {}", self.message)
    }
}

impl std::error::Error for ServerError {}

impl std::fmt::Display for ServerErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind_str = match self {
            ServerErrorKind::InvalidSignature => "Invalid Signature",
            ServerErrorKind::UsernameTaken => "Username Taken",
            ServerErrorKind::TimestampFailure => "Timestamp Failure",
            ServerErrorKind::Unknown => "Unknown Error",
        };
        write!(f, "{}", kind_str)
    }
}

impl ServerError {
    fn new(kind: ServerErrorKind, message: &str) -> ServerError {
        ServerError {
            kind,
            message: message.to_string(),
        }
    }

    pub fn invalid_signature(message: &str) -> ServerError {
        ServerError::new(ServerErrorKind::InvalidSignature, message)
    }

    pub fn username_taken(message: &str) -> ServerError {
        ServerError::new(ServerErrorKind::UsernameTaken, message)
    }

    pub fn timestamp_failure(message: &str) -> ServerError {
        ServerError::new(ServerErrorKind::TimestampFailure, message)
    }

    pub fn unknown(message: &str) -> ServerError {
        ServerError::new(ServerErrorKind::Unknown, message)
    }
}
