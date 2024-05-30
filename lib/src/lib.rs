//! Library for the chat server and client.
//! Includes functions for TCP communication, database access and message and error types.

pub mod errors;
pub mod messages;
pub mod sql;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

use log::{error, warn};
use messages::Message;
use serde_json;
use std::io::{Error, ErrorKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Join multiple vectors into one.
#[macro_export]
macro_rules! joined_vec {
    ($($item:expr),*) => {{
        let mut joined_vec: Vec<u8> = Vec::new();
        $( joined_vec.extend($item); )*
        joined_vec
    }};
}

/// Log an error and return an error.
#[macro_export]
macro_rules! log_and_err {
    ($msg:expr $(, $arg:expr)*) => {{
        let formatted_msg = format!($msg $(, $arg)*);
        error!("{}", formatted_msg);
        Err(Box::new(Error::new(ErrorKind::InvalidData, formatted_msg)))
    }};
}

/// Send a Message to a stream.
pub async fn send_msg(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    message: &Message,
) -> Result<()> {
    let serialized_message: String = match serde_json::to_string(&message) {
        Ok(s) => s,
        Err(_) => return log_and_err!("Failed to serialize message"),
    };

    let prefixed_message: Vec<u8> = get_msg_with_len_prefix(&serialized_message);

    match stream.write_all(&prefixed_message).await {
        Ok(_) => {}
        Err(e) => {
            return log_and_err!("Failed to send message: {}", e);
        }
    }

    stream.flush().await?;

    Ok(())
}

/// Receive a Message from a stream.
///
/// Return the Message if successful.
///
/// If the stream is closed, an error is returned.
pub async fn receive_msg(stream: &mut tokio::net::tcp::OwnedReadHalf) -> Result<Message> {
    let message_length = read_len_prefix(stream).await;

    if message_length == 0 {
        warn!("Peer disconnected");
        return Err(Box::new(Error::new(
            ErrorKind::ConnectionAborted,
            "Peer disconnected",
        )));
    }

    const MAX_MESSAGE_LENGTH: u32 = 10 * 1024 * 1024; // 10 MB

    if message_length > MAX_MESSAGE_LENGTH {
        return log_and_err!("Message too long: {}", message_length);
    }

    let mut buf: Vec<u8> = vec![0; message_length as usize];

    match stream.read_exact(&mut buf).await {
        Ok(_) => (),
        Err(e) => {
            return log_and_err!("Failed to read message from stream. {}", e);
        }
    }

    let content: String = match String::from_utf8(buf.clone()) {
        Ok(s) => s,
        Err(e) => {
            return log_and_err!("Failed to convert message to string. {}", e);
        }
    };

    let message: Message = match serde_json::from_str(&content) {
        Ok(m) => m,
        Err(e) => {
            return log_and_err!("Failed to deserialize message. {}", e);
        }
    };

    Ok(message)
}

/// Prefix a message with its length.
///
/// The length is a 4-byte big-endian integer.
///
/// Returns a vector of bytes.
pub fn get_msg_with_len_prefix(message: &String) -> Vec<u8> {
    let mut prefixed_message: Vec<u8> = vec![0; message.len() + 4];
    prefixed_message[0..4].copy_from_slice(&(message.len() as u32).to_be_bytes());
    prefixed_message[4..].copy_from_slice(&message.as_bytes());
    prefixed_message
}

/// Read a length prefix from a stream.
///
/// The length is a 4-byte big-endian integer.
///
/// Returns the length as a u32.
///
/// If the prefix cannot be read, 0 is returned.
pub async fn read_len_prefix(stream: &mut tokio::net::tcp::OwnedReadHalf) -> u32 {
    let mut length_prefix: [u8; 4] = [0; 4];

    match stream.read_exact(&mut length_prefix).await {
        Ok(_) => (),
        Err(_) => {
            return 0;
        }
    }

    u32::from_be_bytes(length_prefix)
}
