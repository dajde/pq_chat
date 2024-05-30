//! Functions for interacting with the SQLite database.

use self::messages::{ContactRequest, KemBundles, KemCipherText, TextMessage};
use crate::{messages::KemBundle, *};
use log::{error, info};
use sqlite::{Connection, State};
use std::{
    io::{Error, ErrorKind},
    sync::Arc,
};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex, MutexGuard,
};

/// Create KEM bundle table.
pub fn create_kem_bundles_table_user() -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    connection.execute(
        "
        DROP TABLE IF EXISTS kem_bundles;
        CREATE TABLE IF NOT EXISTS kem_bundles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            public_key BLOB NOT NULL,
            signature BLOB NOT NULL,
            timestamp INTEGER NOT NULL,
            uuid BLOB NOT NULL
        )",
    )?;

    info!("sql: KEM bundles table created");
    Ok(())
}

/// Store KEM bundle.
pub fn store_kem_bundle_user(
    owner: &str,
    public_key: &[u8],
    signature: &[u8],
    timestamp: i64,
    uuid: &[u8],
) -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        INSERT INTO kem_bundles (owner, public_key, signature, timestamp, uuid)
        VALUES (?, ?, ?, ?, ?);
        ",
    )?;

    statement.bind((1, owner))?;
    statement.bind((2, public_key))?;
    statement.bind((3, signature))?;
    statement.bind((4, timestamp))?;
    statement.bind((5, uuid))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: KEM bundle stored");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to store KEM bundle");
        }
    }
}

/// Get single KEM bundle for the corresponding owner.
///
/// Returns the KEM bundle.
///
/// If no KEM bundle is found, an error is returned.
pub fn get_single_kem_bundle_by_owner(owner: &str) -> Result<KemBundle> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        SELECT public_key, signature, timestamp, uuid FROM kem_bundles WHERE owner = ? ;
        ",
    )?;

    statement.bind((1, owner))?;

    let result: State = statement.next()?;

    match result {
        State::Row => {
            let public_key: Vec<u8> = statement.read(0)?;
            let signature: Vec<u8> = statement.read(1)?;
            let timestamp: i64 = statement.read(2)?;
            let uuid: Vec<u8> = statement.read(3)?;

            info!("sql: KEM bundle retrieved");

            Ok(KemBundle {
                owner: owner.to_string(),
                recipient: "".to_string(),
                pub_kem: public_key,
                signature,
                validity: timestamp,
                uuid,
            })
        }
        _ => {
            return log_and_err!("sql: Failed to retrieve KEM bundle");
        }
    }
}

/// Delete KEM bundle by uuid.
pub fn delete_kem_bundle_user_by_uuid(uuid: &[u8]) -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        DELETE FROM kem_bundles WHERE uuid = ?;
        ",
    )?;

    statement.bind((1, uuid))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: KEM bundle removed");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to remove KEM bundle");
        }
    }
}

/// Create contacts table.
pub fn create_contacts_table() -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    connection.execute(
        "
        DROP TABLE IF EXISTS contacts;
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL
        )",
    )?;

    info!("sql: Contacts table created");
    Ok(())
}

/// Store contact.
pub fn store_contact(username: &str) -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        INSERT INTO contacts (username)
        VALUES (?);
        ",
    )?;

    statement.bind((1, username))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: Contact stored");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to store contact");
        }
    }
}

/// Get all contacts.
///
/// Returns a vector of contacts.
///
/// If no contacts are found, an empty vector is returned.
pub fn get_contacts() -> Result<Vec<String>> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        SELECT username FROM contacts;
        ",
    )?;

    let mut friends: Vec<String> = Vec::new();

    loop {
        let result: State = statement.next()?;

        match result {
            State::Row => {
                let username: String = statement.read(0)?;
                friends.push(username);
            }
            State::Done => {
                break;
            }
        }
    }

    info!("sql: Contacts retrieved");
    Ok(friends)
}

/// Create contact requests table.
pub fn create_contact_requests_table() -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    connection.execute(
        "
        DROP TABLE IF EXISTS requests;
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester TEXT NOT NULL
        )",
    )?;

    info!("sql: Contact requests table created");
    Ok(())
}

/// Store contact request.
pub fn store_contact_request(from: &str) -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        INSERT INTO requests (requester)
        VALUES (?);
        ",
    )?;

    statement.bind((1, from))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: Contact request stored");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to store contact request");
        }
    }
}

/// Get all contact requests.
///
/// Returns a vector of contact requests.
///
/// If no contact requests are found, an empty vector is returned.
pub fn get_contact_requests() -> Result<Vec<String>> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        SELECT requester FROM requests;
        ",
    )?;

    let mut requests: Vec<String> = Vec::new();

    loop {
        let result: State = statement.next()?;

        match result {
            State::Row => {
                let from: String = statement.read(0)?;
                requests.push(from);
            }
            State::Done => {
                break;
            }
        }
    }

    info!("sql: Contact requests retrieved");
    Ok(requests)
}

/// Delete contact request by requester.
pub fn remove_contact_request(from: &str) -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        DELETE FROM requests WHERE requester = ?;
        ",
    )?;

    statement.bind((1, from))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: Contact request removed");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to remove contact request");
        }
    }
}

/// Create private KEM key table.
pub fn create_privkem_table() -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    connection.execute(
        "
        DROP TABLE IF EXISTS priv_kem;
        CREATE TABLE IF NOT EXISTS priv_kem (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            private_key BLOB NOT NULL,
            timestamp INTEGER NOT NULL,
            uuid BLOB NOT NULL
        )",
    )?;

    info!("sql: Private KEM key table created");
    Ok(())
}

/// Store private KEM key.
pub fn store_privkem(
    recipient: &str,
    private_key: &[u8],
    validity: i64,
    uuid: &[u8],
) -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        INSERT INTO priv_kem (recipient, private_key, timestamp, uuid)
        VALUES (?, ?, ?, ?);
        ",
    )?;

    statement.bind((1, recipient))?;
    statement.bind((2, private_key))?;
    statement.bind((3, validity))?;
    statement.bind((4, uuid))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: Private KEM key stored");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to store private KEM key");
        }
    }
}

/// Get private KEM key by recipient.
///
/// Returns the private key and validity timestamp.
///
/// If the private KEM key is not found, an error is returned.
pub fn get_privkem_by_uuid(uuid: &[u8]) -> Result<(Vec<u8>, i64)> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        SELECT private_key, timestamp FROM priv_kem WHERE uuid = ?;
        ",
    )?;

    statement.bind((1, uuid))?;

    let result: State = statement.next()?;

    match result {
        State::Row => {
            let private_key: Vec<u8> = statement.read(0)?;
            let validity: i64 = statement.read(1)?;
            info!("sql: Private KEM key retrieved");
            Ok((private_key, validity))
        }
        _ => {
            return log_and_err!("sql: Failed to retrieve private KEM key");
        }
    }
}

/// Get all private KEM keys.
///
/// Returns a vector of tuples containing the uuid, recipient, private key and validity timestamp.
///
/// Returns an empty vector if no private KEM keys are found.
pub fn get_all_privkem() -> Result<Vec<(Vec<u8>, String, Vec<u8>, i64)>> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        SELECT uuid, recipient, private_key, timestamp FROM priv_kem;
        ",
    )?;

    let mut priv_kem_vec: Vec<(Vec<u8>, String, Vec<u8>, i64)> = Vec::new();

    loop {
        let result: State = statement.next()?;

        match result {
            State::Row => {
                let uuid: Vec<u8> = statement.read(0)?;
                let recipient: String = statement.read(1)?;
                let private_key: Vec<u8> = statement.read(2)?;
                let timestamp: i64 = statement.read(3)?;
                priv_kem_vec.push((uuid, recipient, private_key, timestamp));
            }
            State::Done => {
                break;
            }
        }
    }

    info!("sql: Private KEM keys retrieved");
    Ok(priv_kem_vec)
}

/// Delete private KEM key by uuid.
pub fn delete_privkem(uuid: &[u8]) -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        DELETE FROM priv_kem WHERE uuid = ?;
        ",
    )?;

    statement.bind((1, uuid))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: Private KEM key removed");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to remove private KEM key");
        }
    }
}

/// Create session key table.
pub fn create_session_key_table() -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    connection.execute(
        "
        DROP TABLE IF EXISTS session_keys;
        CREATE TABLE IF NOT EXISTS session_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            session_key BLOB NOT NULL,
            timestamp INTEGER NOT NULL
        )",
    )?;

    info!("sql: Session key table created");
    Ok(())
}

/// Store session key.
pub fn store_session_key(recipient: &str, session_key: &[u8], timestamp: i64) -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        INSERT INTO session_keys (recipient, session_key, timestamp)
        VALUES (?, ?, ?);
        ",
    )?;

    statement.bind((1, recipient))?;
    statement.bind((2, session_key))?;
    statement.bind((3, timestamp))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: Session key stored");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to store session key");
        }
    }
}

/// Get latest session key by recipient.
///
/// Returns the session key and validity timestamp.
///
/// Returns an empty vector and 0 for timestamp if no session key is found.
pub fn get_latest_session_key(recipient: &str) -> Result<(Vec<u8>, i64)> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        SELECT session_key, timestamp FROM session_keys WHERE recipient = ? ORDER BY timestamp DESC LIMIT 1;
        ",
    )?;

    statement.bind((1, recipient))?;

    let result: State = statement.next()?;

    match result {
        State::Row => {
            let session_key: Vec<u8> = statement.read(0)?;
            let timestamp: i64 = statement.read(1)?;
            info!("sql: Session key retrieved");
            Ok((session_key, timestamp))
        }
        State::Done => {
            info!("sql: No session key found");
            Ok((Vec::new(), 0))
        }
    }
}

/// Get all session keys by recipient.
///
/// Returns a vector of tuples containing the session key and validity timestamp.
///
/// Returns an empty vector if no session keys are found.
pub fn get_all_session_keys_by_recipient(recipient: &str) -> Result<Vec<(Vec<u8>, i64)>> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        SELECT session_key, timestamp FROM session_keys WHERE recipient = ?;
        ",
    )?;

    statement.bind((1, recipient))?;

    let mut session_keys: Vec<(Vec<u8>, i64)> = Vec::new();

    loop {
        let result: State = statement.next()?;

        match result {
            State::Row => {
                let session_key: Vec<u8> = statement.read(0)?;
                let timestamp: i64 = statement.read(1)?;
                session_keys.push((session_key, timestamp));
            }
            State::Done => {
                break;
            }
        }
    }

    info!("sql: Session keys retrieved");
    Ok(session_keys)
}

/// Get all session keys.
///
/// Returns a vector of tuples containing the session key id, recipient, session key and validity timestamp.
///
/// Returns an empty vector if no session keys are found.
pub fn get_all_session_keys() -> Result<Vec<(i64, String, Vec<u8>, i64)>> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        SELECT id, recipient, session_key, timestamp FROM session_keys;
        ",
    )?;

    let mut session_keys: Vec<(i64, String, Vec<u8>, i64)> = Vec::new();

    loop {
        let result: State = statement.next()?;

        match result {
            State::Row => {
                let id: i64 = statement.read(0)?;
                let recipient: String = statement.read(0)?;
                let session_key: Vec<u8> = statement.read(1)?;
                let timestamp: i64 = statement.read(2)?;
                session_keys.push((id, recipient, session_key, timestamp));
            }
            State::Done => {
                break;
            }
        }
    }

    info!("sql: Session keys retrieved");
    Ok(session_keys)
}

/// Delete session key by id.
pub fn delete_session_key(id: i64) -> Result<()> {
    let connection: Connection = Connection::open("store.db")?;

    let mut statement = connection.prepare(
        "
        DELETE FROM session_keys WHERE id = ?;
        ",
    )?;

    statement.bind((1, id))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: Session key removed");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to remove session key");
        }
    }
}

/// Create public DSA key table.
pub fn create_pubdsa_table() -> Result<()> {
    let connection: Connection = Connection::open("keys.db")?;

    connection.execute(
        "
        DROP TABLE IF EXISTS pub_dsa;
        CREATE TABLE IF NOT EXISTS pub_dsa (
            username TEXT NOT NULL PRIMARY KEY,
            public_key BLOB NOT NULL,
            signature BLOB NOT NULL
        )",
    )?;

    info!("sql: Public DSA key table created");
    Ok(())
}

/// Store public DSA key.
pub fn store_pubdsa(
    connection: &MutexGuard<Connection>,
    username: &str,
    public_key: &[u8],
    signature: &[u8],
) -> Result<()> {
    let mut statement = connection.prepare(
        "
        INSERT INTO pub_dsa (username, public_key, signature)
        VALUES (?, ?, ?);
        ",
    )?;

    statement.bind((1, username))?;
    statement.bind((2, public_key))?;
    statement.bind((3, signature))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: Public DSA key stored");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to store public DSA key");
        }
    }
}

/// Get public DSA key by username.
///
/// Returns the public key and signature.
///
/// If the public DSA key is not found, an error is returned.
pub fn get_pubdsa(
    connection: &MutexGuard<Connection>,
    username: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut statement = connection.prepare(
        "
        SELECT public_key, signature FROM pub_dsa WHERE username = ?;
        ",
    )?;

    statement.bind((1, username))?;

    let result: State = statement.next()?;

    match result {
        State::Row => {
            let public_key: Vec<u8> = statement.read(0)?;
            let signature: Vec<u8> = statement.read(1)?;

            info!("sql: Public DSA key retrieved");
            Ok((public_key, signature))
        }
        _ => {
            return log_and_err!("sql: Failed to retrieve public DSA key");
        }
    }
}

/// Create messages tables.
pub fn create_messages_tables() -> Result<()> {
    let connection: Connection = Connection::open("data.db")?;

    connection.execute(
        "
        DROP TABLE IF EXISTS text_messages;
        CREATE TABLE IF NOT EXISTS text_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            content BLOB NOT NULL,
            nonce BLOB NOT NULL,
            timestamp INTEGER NOT NULL
        )",
    )?;

    connection.execute(
        "
        DROP TABLE IF EXISTS kem_cipher_texts;
        CREATE TABLE IF NOT EXISTS kem_cipher_texts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            uuid BLOB NOT NULL,
            signature BLOB NOT NULL,
            sk_validity INTEGER NOT NULL
        )",
    )?;

    connection.execute(
        "
        DROP TABLE IF EXISTS contact_requests;
        CREATE TABLE IF NOT EXISTS contact_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            sender TEXT NOT NULL,
            recipient TEXT NOT NULL
        )",
    )?;

    info!("sql: Messages table created");
    Ok(())
}

/// Store message for later delivery.
pub fn store_message(message: &Message, connection: MutexGuard<Connection>) -> Result<()> {
    message.store(&connection)
}

impl Storable for Message {
    fn store(&self, connection: &Connection) -> Result<()> {
        match self {
            Message::TextMessage(message) => message.store(connection),
            Message::KemCipherText(message) => message.store(connection),
            Message::ContactRequest(message) => message.store(connection),
            _ => {
                return log_and_err!("sql: Unsupported message type");
            }
        }
    }
}

pub trait Storable {
    fn store(&self, connection: &Connection) -> Result<()>;
}

impl Storable for TextMessage {
    fn store(&self, connection: &Connection) -> Result<()> {
        let mut statement = connection.prepare(
            "
            INSERT INTO text_messages (sender, recipient, content, nonce, timestamp)
            VALUES (?, ?, ?, ?, ?);
            ",
        )?;

        statement.bind((1, &self.from as &str))?;
        statement.bind((2, &self.to as &str))?;
        statement.bind((3, &self.content as &[u8]))?;
        statement.bind((4, &self.nonce as &[u8]))?;
        statement.bind((5, self.sent_timestamp))?;

        let result: State = statement.next()?;

        match result {
            State::Done => {
                info!("sql: Text message stored");
                Ok(())
            }
            _ => {
                return log_and_err!("sql: Failed to store text message");
            }
        }
    }
}

impl Storable for KemCipherText {
    fn store(&self, connection: &Connection) -> Result<()> {
        let mut statement = connection.prepare(
            "
            INSERT INTO kem_cipher_texts (sender, recipient, ciphertext, uuid, signature, sk_validity)
            VALUES (?, ?, ?, ?, ?, ?);
            ",
        )?;

        statement.bind((1, &self.from as &str))?;
        statement.bind((2, &self.to as &str))?;
        statement.bind((3, &self.ciphertext as &[u8]))?;
        statement.bind((4, &self.uuid as &[u8]))?;
        statement.bind((5, &self.signature as &[u8]))?;
        statement.bind((6, self.sk_validity))?;

        let result: State = statement.next()?;

        match result {
            State::Done => {
                info!("sql: KEM cipher text stored");
                Ok(())
            }
            _ => {
                return log_and_err!("sql: Failed to store KEM cipher text");
            }
        }
    }
}

impl Storable for ContactRequest {
    fn store(&self, connection: &Connection) -> Result<()> {
        let mut statement = connection.prepare(
            "
            INSERT INTO contact_requests (sender, recipient)
            VALUES (?, ?);
            ",
        )?;

        statement.bind((1, &self.from as &str))?;
        statement.bind((2, &self.to as &str))?;

        let result: State = statement.next()?;

        match result {
            State::Done => {
                info!("sql: Contact request stored");
                Ok(())
            }
            _ => {
                return log_and_err!("sql: Failed to store contact request");
            }
        }
    }
}

/// DB request enum for async communication with DB thread.
pub enum DbRequest {
    GetAllMessages {
        recipient: String,
        response: Sender<Vec<Message>>,
    },
    StoreMessage {
        message: Message,
        response: Sender<()>,
    },
    DeleteAllMessages {
        recipient: String,
        response: Sender<()>,
    },
}

/// Initialize DB thread for async communication with the database.
pub fn db_thread(mut rx: Receiver<DbRequest>, db_mutex: Arc<Mutex<Connection>>) {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!(
                "Failed to create tokio runtime while starting DB thread. {}",
                e
            );
            return;
        }
    };

    rt.block_on(async move {
        while let Some(request) = rx.recv().await {
            let connection = db_mutex.lock().await;

            match request {
                DbRequest::GetAllMessages {
                    recipient,
                    response,
                } => {
                    let messages = match get_all_messages(&recipient, connection) {
                        Ok(messages) => messages,
                        Err(e) => {
                            error!("sql: Failed to get messages. {}", e);
                            Vec::new()
                        }
                    };
                    match response.send(messages).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("sql: Failed to send response. {}", e);
                        }
                    }
                }
                DbRequest::StoreMessage { message, response } => {
                    match store_message(&message, connection) {
                        Ok(_) => {
                            info!("sql: Message stored");
                        }
                        Err(e) => {
                            error!("sql: Failed to store message. {}", e);
                        }
                    }
                    match response.send(()).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("sql: Failed to send response. {}", e);
                        }
                    }
                }
                DbRequest::DeleteAllMessages {
                    recipient,
                    response,
                } => {
                    match remove_all_messages(&recipient, connection) {
                        Ok(_) => {
                            info!("sql: Messages removed");
                        }
                        Err(e) => {
                            error!("sql: Failed to remove messages. {}", e);
                        }
                    }

                    match response.send(()).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("sql: Failed to send response. {}", e);
                        }
                    }
                }
            }
        }
    });
}

/// Get all stored messages for the corresponding recipient.
///
/// Returns a vector of messages.
///
/// If no messages are found, an empty vector is returned.
pub fn get_all_messages(
    recipient: &str,
    connection: MutexGuard<Connection>,
) -> Result<Vec<Message>> {
    let mut messages: Vec<Message> = Vec::new();

    let mut statement = connection
        .prepare(
            "
        SELECT sender, recipient, ciphertext, uuid, signature, sk_validity FROM kem_cipher_texts WHERE recipient = ?;
        ",
        )?;

    statement.bind((1, recipient))?;

    loop {
        let result: State = statement.next()?;

        match result {
            State::Row => {
                let from: String = statement.read(0)?;
                let to: String = statement.read(1)?;
                let ciphertext: Vec<u8> = statement.read(2)?;
                let uuid: Vec<u8> = statement.read(3)?;
                let signature: Vec<u8> = statement.read(4)?;
                let sk_validity: i64 = statement.read(5)?;

                let message = Message::KemCipherText(KemCipherText {
                    from,
                    to,
                    ciphertext,
                    uuid,
                    signature,
                    sk_validity,
                });

                messages.push(message);
            }
            State::Done => {
                break;
            }
        }
    }

    let mut statement = connection.prepare(
        "
        SELECT sender, recipient, content, nonce, timestamp FROM text_messages WHERE recipient = ?;
        ",
    )?;

    statement.bind((1, recipient))?;

    loop {
        let result: State = statement.next()?;

        match result {
            State::Row => {
                let from: String = statement.read(0)?;
                let to: String = statement.read(1)?;
                let content: Vec<u8> = statement.read(2)?;
                let nonce: Vec<u8> = statement.read(3)?;
                let timestamp: i64 = statement.read(4)?;

                let message = Message::TextMessage(TextMessage {
                    from,
                    to,
                    content,
                    nonce,
                    sent_timestamp: timestamp,
                });

                messages.push(message);
            }
            State::Done => {
                break;
            }
        }
    }

    let mut statement = connection.prepare(
        "
        SELECT sender, recipient FROM contact_requests WHERE recipient = ?;
        ",
    )?;

    statement.bind((1, recipient))?;

    loop {
        let result: State = statement.next()?;

        match result {
            State::Row => {
                let from: String = statement.read(0)?;
                let to: String = statement.read(1)?;

                let message = Message::ContactRequest(ContactRequest { from, to });
                messages.push(message);
            }
            State::Done => {
                break;
            }
        }
    }

    Ok(messages)
}

/// Remove all stored messages for the corresponding recipient.
pub fn remove_all_messages(
    recipient: &str,
    connection: tokio::sync::MutexGuard<Connection>,
) -> Result<()> {
    // Delete KEM ciphertexts
    let mut statement = connection.prepare(
        "
        DELETE FROM kem_cipher_texts WHERE recipient = ?;
        ",
    )?;

    statement.bind((1, recipient))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: KEM cipher texts removed");
        }
        _ => {
            error!("sql: Failed to remove KEM cipher texts");
        }
    }

    // Delete text messages
    let mut statement = connection.prepare(
        "
        DELETE FROM text_messages WHERE recipient = ?;
        ",
    )?;

    statement.bind((1, recipient))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: Text messages removed");
        }
        _ => {
            error!("sql: Failed to remove text messages");
        }
    }

    // Delete contact requests
    let mut statement = connection.prepare(
        "
        DELETE FROM contact_requests WHERE recipient = ?;
        ",
    )?;

    statement.bind((1, recipient))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: Contact requests removed");
        }
        _ => {
            error!("sql: Failed to remove contact requests");
        }
    }

    info!("sql: Messages removed");
    Ok(())
}

/// Create KEM bundles table.
pub fn create_kem_bundle_table() -> Result<()> {
    let connection: Connection = Connection::open("keys.db")?;

    connection.execute(
        "
        DROP TABLE IF EXISTS kem_bundles;
        CREATE TABLE IF NOT EXISTS kem_bundles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            recipient TEXT NOT NULL,
            public_key BLOB NOT NULL,
            signature BLOB NOT NULL,
            timestamp INTEGER NOT NULL,
            uuid BLOB NOT NULL
        )",
    )?;

    info!("sql: KEM bundles table created");
    Ok(())
}

/// Store KEM bundle.
pub fn store_kem_bundle(
    connection: &MutexGuard<Connection>,
    owner: &str,
    recipient: &str,
    public_key: &[u8],
    signature: &[u8],
    timestamp: i64,
    uuid: &[u8],
) -> Result<()> {
    let mut statement = connection.prepare(
        "
        INSERT INTO kem_bundles (owner, recipient, public_key, signature, timestamp, uuid)
        VALUES (?, ?, ?, ?, ?, ?);
        ",
    )?;

    statement.bind((1, owner))?;
    statement.bind((2, recipient))?;
    statement.bind((3, public_key))?;
    statement.bind((4, signature))?;
    statement.bind((5, timestamp))?;
    statement.bind((6, uuid))?;

    let result: State = statement.next()?;

    match result {
        State::Done => {
            info!("sql: KEM bundle stored");
            Ok(())
        }
        _ => {
            return log_and_err!("sql: Failed to store KEM bundle");
        }
    }
}

/// Get all KEM bundles for the corresponding user pair.
///
/// Returns a vector of KEM bundles.
///
/// If no KEM bundles are found, an empty KEM bundles struct is returned.
pub fn get_kem_bundles(
    connection: &MutexGuard<Connection>,
    owner: &str,
    recipient: &str,
) -> Result<KemBundles> {
    let mut statement = connection.prepare(
        "
        SELECT public_key, signature, timestamp, uuid FROM kem_bundles WHERE owner = ? AND recipient = ?;
        ",
    )?;

    statement.bind((1, owner))?;
    statement.bind((2, recipient))?;

    let mut kem_bundles: KemBundles = KemBundles { data: Vec::new() };

    loop {
        match statement.next()? {
            State::Row => {
                let public_key: Vec<u8> = statement.read(0)?;
                let signature: Vec<u8> = statement.read(1)?;
                let timestamp: i64 = statement.read(2)?;
                let uuid: Vec<u8> = statement.read(3)?;

                info!("sql: KEM bundle retrieved");

                let kem_bundle = KemBundle {
                    owner: owner.to_string(),
                    recipient: recipient.to_string(),
                    pub_kem: public_key,
                    uuid,
                    signature,
                    validity: timestamp,
                };

                kem_bundles.data.push(kem_bundle);
            }
            State::Done => {
                break;
            }
        }
    }

    let mut statement =
        connection.prepare("DELETE FROM kem_bundles WHERE owner = ? AND recipient = ?;")?;

    statement.bind((1, owner))?;
    statement.bind((2, recipient))?;

    let result: State = statement.next()?;
    match result {
        State::Done => {
            info!("sql: KEM bundles removed");
        }
        _ => {
            error!("sql: Failed to remove KEM bundles");
        }
    }

    info!("sql: KEM bundles retrieved");
    Ok(kem_bundles)
}
