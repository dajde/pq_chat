//! This module contains the definition of the messages exchanged between the client and the server.

use crate::errors::ServerError;
use serde::{Deserialize, Serialize};

impl Message {
    pub fn sender(&self) -> &str {
        match self {
            Message::TextMessage(msg) => &msg.from,
            Message::KemCipherText(msg) => &msg.from,
            Message::RegisterRequest(msg) => &msg.username,
            Message::KemBundle(msg) => &msg.owner,
            Message::ContactRequest(msg) => &msg.from,
            Message::PubDsa(msg) => &msg.username,
            Message::KemBundleRequest(msg) => &msg.recipient,
            _ => "",
        }
    }

    pub fn recipient(&self) -> &str {
        match self {
            Message::TextMessage(msg) => &msg.to,
            Message::KemCipherText(msg) => &msg.to,
            Message::KemBundle(msg) => &msg.recipient,
            Message::ContactRequest(msg) => &msg.to,
            Message::KemBundleRequest(msg) => &msg.owner,
            _ => "",
        }
    }

    pub fn kind(&self) -> &str {
        match self {
            Message::TextMessage(_) => "TextMessage",
            Message::KemCipherText(_) => "KemCipherText",
            Message::RegisterRequest(_) => "RegisterRequest",
            Message::RegisterResponse(_) => "RegisterResponse",
            Message::KemBundle(_) => "KemBundle",
            Message::ContactRequest(_) => "ContactRequest",
            Message::PubDsaRequest(_) => "PubDsaRequest",
            Message::PubDsa(_) => "PubDsa",
            Message::KemBundleRequest(_) => "KemBundleRequest",
            Message::KemBundles(_) => "KemBundles",
            Message::StoredMessagesResponse(_) => "StoredMessagesResponse",
            Message::ServerGreeting(_) => "ServerGreeting",
            Message::ErrorResponse(_) => "ErrorMessage",
        }
    }
}

#[derive(Deserialize, Serialize)]
pub enum Message {
    TextMessage(TextMessage),
    KemCipherText(KemCipherText),
    RegisterRequest(RegisterRequest),
    RegisterResponse(RegisterResponse),
    KemBundle(KemBundle),
    ContactRequest(ContactRequest),
    PubDsaRequest(PubDsaRequest),
    PubDsa(PubDsa),
    KemBundleRequest(KemBundleRequest),
    KemBundles(KemBundles),
    StoredMessagesResponse(StoredMessagesResponse),
    ServerGreeting(ServerGreeting),
    ErrorResponse(ErrorResponse),
}

#[derive(Deserialize, Serialize)]
pub struct TextMessage {
    pub from: String,
    pub to: String,
    pub content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub sent_timestamp: i64,
}

#[derive(Deserialize, Serialize)]
pub struct KemBundle {
    pub owner: String,
    pub recipient: String,
    pub pub_kem: Vec<u8>,
    pub uuid: Vec<u8>,
    pub signature: Vec<u8>,
    pub validity: i64,
}

#[derive(Deserialize, Serialize)]
pub struct KemCipherText {
    pub from: String,
    pub to: String,
    pub ciphertext: Vec<u8>,
    pub uuid: Vec<u8>,
    pub signature: Vec<u8>,
    pub sk_validity: i64,
}

#[derive(Deserialize, Serialize)]
pub struct KemBundleRequest {
    pub owner: String,
    pub recipient: String,
    pub signature: Vec<u8>,
    pub timestamp: i64,
}

#[derive(Deserialize, Serialize)]
pub struct KemBundles {
    pub data: Vec<KemBundle>,
}

#[derive(Deserialize, Serialize)]
pub struct PubDsaRequest {
    pub username: String,
}
#[derive(Deserialize, Serialize)]
pub struct PubDsa {
    pub username: String,
    pub pub_dsa: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterRequest {
    pub username: String,
    pub signature: Vec<u8>,
    pub pub_dsa: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterResponse {
    pub signature: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
pub struct ContactRequest {
    pub from: String,
    pub to: String,
}

#[derive(Deserialize, Serialize)]
pub struct ServerGreeting {
    pub username: String,
}

#[derive(Deserialize, Serialize)]
pub struct StoredMessagesResponse {
    pub messages: Vec<Message>,
}

#[derive(Deserialize, Serialize)]
pub struct ErrorResponse {
    pub error: ServerError,
}
