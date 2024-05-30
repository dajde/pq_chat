use lib::{messages::*, sql::*, *};
use log::{error, info};
use simplelog::*;
use sqlite::Connection;
use std::{fs::File, sync::Arc};
use tokio::sync::{Mutex, MutexGuard};

struct Client {
    pub stream: tokio::net::tcp::OwnedWriteHalf,
    pub name: String,
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    online_clients: Arc<Mutex<Vec<Client>>>,
    db_tx: tokio::sync::mpsc::Sender<DbRequest>,
) {
    let username: String;

    let (mut tcpreader, mut tcpwriter) = stream.into_split();

    match receive_msg(&mut tcpreader).await {
        Ok(Message::ServerGreeting(message)) => {
            info!("server: {} has connected", message.username);
            username = message.username;
        }
        _ => {
            error!("server: Expected server greeting, got something else. Terminating connection");
            return;
        }
    }

    // Send stored messages
    let mut stored_messages_response = StoredMessagesResponse {
        messages: Vec::new(),
    };

    // Send stored messages
    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel(1);
    db_tx
        .send(DbRequest::GetAllMessages {
            recipient: username.clone(),
            response: response_tx,
        })
        .await
        .expect("Failed to send DB request");

    let messages: Vec<Message> = match response_rx.recv().await {
        Some(messages) => messages,
        _ => {
            error!("server: Expected messages, got something else. Terminating connection");
            return;
        }
    };

    if messages.len() > 0 {
        for message in messages {
            info!(
                "server: Sending stored message FROM: {} TO: {} CONTENT: {}",
                message.sender(),
                message.recipient(),
                message.kind(),
            );

            stored_messages_response.messages.push(message);
        }
    }

    let message = Message::StoredMessagesResponse(stored_messages_response);

    send_msg(&mut tcpwriter, &message)
        .await
        .expect("Failed to send stored messages");

    // Delete stored messages
    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel(1);
    db_tx
        .send(DbRequest::DeleteAllMessages {
            recipient: username.clone(),
            response: response_tx,
        })
        .await
        .expect("Failed to send DB request");

    response_rx
        .recv()
        .await
        .expect("Failed to receive DB response");

    // Create client
    let client: Client = Client {
        stream: tcpwriter,
        name: username.clone(),
    };

    // Add client to online clients
    {
        let mut online_clients_guard: MutexGuard<'_, Vec<Client>> = online_clients.lock().await;
        online_clients_guard.push(client);
    }

    // Message receiving loop
    loop {
        let message: Message;

        match receive_msg(&mut tcpreader).await {
            Ok(m) => {
                message = m;
            }
            Err(_) => {
                info!("server: Client {} has disconnected", username);
                let mut online_clients_guard: MutexGuard<'_, Vec<Client>> =
                    online_clients.lock().await;
                online_clients_guard.retain(|client: &Client| client.name != username);
                return;
            }
        }

        info!(
            "server: FROM: {} TO: {} CONTENT: {}",
            message.sender(),
            message.recipient(),
            message.kind()
        );

        let mut online_clients_guard: MutexGuard<'_, Vec<Client>> = online_clients.lock().await;

        // Send message to recipient if online, otherwise store it
        match online_clients_guard
            .iter_mut()
            .find(|client| client.name == message.recipient())
        {
            Some(recipient) => match send_msg(&mut recipient.stream, &message).await {
                Ok(_) => {
                    info!("server: Message sent to {}", recipient.name)
                }
                Err(_) => {
                    error!("server: Failed to send message to {}", recipient.name);
                    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel(1);
                    db_tx
                        .send(DbRequest::StoreMessage {
                            message,
                            response: response_tx,
                        })
                        .await
                        .expect("Failed to send DB request");

                    response_rx
                        .recv()
                        .await
                        .expect("Failed to receive DB response");
                }
            },
            None => {
                let (response_tx, mut response_rx) = tokio::sync::mpsc::channel(1);
                db_tx
                    .send(DbRequest::StoreMessage {
                        message,
                        response: response_tx,
                    })
                    .await
                    .expect("Failed to send DB request");

                response_rx
                    .recv()
                    .await
                    .expect("Failed to receive DB response");
            }
        }
    }
}

#[tokio::main]
async fn main() {
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            File::create("log").unwrap(),
        ),
    ])
    .unwrap();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    info!(
        "server: Server started on {}",
        listener.local_addr().unwrap()
    );

    let (db_tx, db_rx) = tokio::sync::mpsc::channel(32);
    let db_path = "data.db".to_string();

    // Initialize the SQLite connection and wrap it in a mutex
    let connection = Connection::open(db_path.clone()).expect("Failed to connect to the database");
    let db_mutex = Arc::new(tokio::sync::Mutex::new(connection));

    // Start the SQLite thread
    {
        let db_mutex = db_mutex.clone();
        std::thread::spawn(move || {
            sql::db_thread(db_rx, db_mutex);
        });
    }

    create_messages_tables().expect("Failed to create tables");

    let online_clients: Arc<Mutex<Vec<Client>>> = Arc::new(Mutex::new(Vec::new()));

    loop {
        let (stream, _) = listener.accept().await.unwrap();

        let online_clients_clone: Arc<Mutex<Vec<Client>>> = online_clients.clone();

        let db_tx_clone = db_tx.clone();

        tokio::spawn(async move {
            handle_connection(stream, online_clients_clone, db_tx_clone).await;
        });
    }
}
