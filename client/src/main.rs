mod chat_logic;
mod events;
mod terminal;
mod types;
mod update;
mod view;
use chat_logic::*;
use crossterm::{
    cursor,
    terminal::{disable_raw_mode, LeaveAlternateScreen},
    ExecutableCommand,
};
use events::handle_event;
use lib::{messages::*, sql::*, *};
use log::*;
use simplelog::*;
use std::{fs::File, io::stdout, panic, process::exit, sync::mpsc, vec};
use terminal::*;
use types::*;
use update::update_model;
use view::view;

#[tokio::main]
async fn main() {
    // Initialize OQS
    oqs::init();

    // Initialize logger
    WriteLogger::init(
        LevelFilter::Info,
        Config::default(),
        File::create("log").unwrap(),
    )
    .unwrap();

    info!("Starting client");
    let config = match read_or_create_config("config.json") {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to read config file. {e}");
            panic!();
        }
    };

    // Read user data from file or register as a new user
    let (username, priv_dsa) = match File::open("userdata.json") {
        Ok(file) => match read_userdata(file) {
            Ok((username, key)) => (username, key),
            Err(_) => {
                error!("Failed to read userdata");
                panic!();
            }
        },
        Err(_) => {
            info!("No userdata found, registering new user");
            let (username, key) = register_user(&config)
                .await
                .expect("Failed to register user");
            init_userdata(username.clone(), &key).expect("Failed to write userdata");
            init_store().unwrap();
            (username, key)
        }
    };

    // Get contacts and initialize conversations
    let contacts = get_contacts().unwrap();
    let conversations: Vec<Conversation> = contacts
        .iter()
        .map(|contact| Conversation {
            recipient: contact.clone(),
            messages: vec![],
        })
        .collect();

    // Create message receiver thread's channel
    let (tx, rx) = mpsc::channel::<TextMessage>();

    // Get stored messages
    let (mut writer, mut reader) = join_server(&username, &tx, &config, &priv_dsa)
        .await
        .unwrap();

    // Start message receiver thread
    let priv_dsa_clone = priv_dsa.clone();
    let config_clone = config.clone();

    tokio::spawn(async move {
        message_receiver(&mut reader, &priv_dsa_clone, tx, &config_clone).await;
    });

    // Initialize model
    let mut model = Model {
        running_state: RunningState::Running,
        navigation_state: NavigationState::Menu,
        list_selected: 0,
        focus: Focus::Input,
        recipient: String::new(),
        input: String::new(),
        contacts: contacts.clone(),
        contact_requests: vec![],
        username,
        priv_dsa,
        conversations,
        config: config.clone(),
    };

    // Initialize terminal
    let mut terminal = init_terminal().unwrap();

    // Main loop
    while model.running_state != RunningState::Done {
        // Draw the current view
        terminal.draw(|f| view(&model, f)).unwrap();

        // Handle events and get event messages
        let mut current_msg = handle_event(&model, &mut writer).await.unwrap();

        // Handle messages from message receiver thread
        rx.try_iter().for_each(|msg| {
            for conversation in model.conversations.iter_mut() {
                if conversation.recipient == msg.from {
                    conversation.messages.push(ConversationMessage {
                        sender: msg.from.clone(),
                        message: String::from_utf8(msg.content.clone()).unwrap(),
                        timestamp: msg.sent_timestamp,
                    });
                    break;
                }
            }
        });

        // Update model with event messages
        while current_msg.is_some() {
            current_msg = update_model(&mut model, current_msg.unwrap());
        }
    }

    exit_app!("Goodbye!");
}
