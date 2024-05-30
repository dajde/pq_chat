use oqs::sig;
use serde::{Deserialize, Serialize};

/// Holds the state of the application.
pub struct Model {
    pub username: String,
    pub recipient: String,
    pub contacts: Vec<String>,
    pub contact_requests: Vec<String>,
    pub conversations: Vec<Conversation>,
    pub list_selected: usize,
    pub input: String,
    pub running_state: RunningState,
    pub navigation_state: NavigationState,
    pub focus: Focus,
    pub priv_dsa: sig::SecretKey,
    pub config: AppConfig,
}

/// Application configuration.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub keyserver_name: String,
    pub server_name: String,
    pub kem_lifetime: i64,
    pub session_key_lifetime: i64,
    pub kem_grace_period: i64,
    pub session_key_grace_period: i64,
}

/// Represents the focus of the screen.
#[derive(PartialEq, Eq)]
pub enum Focus {
    Input,
    List,
}

/// Contains the recipient and messages of a conversation.
pub struct Conversation {
    pub recipient: String,
    pub messages: Vec<ConversationMessage>,
}

/// Contains the sender, message, and timestamp of a message.
pub struct ConversationMessage {
    pub sender: String,
    pub message: String,
    pub timestamp: i64,
}

/// Represents the running state of the application.
#[derive(PartialEq, Eq)]
pub enum RunningState {
    Running,
    Done,
}

/// Represents the currently active view.
#[derive(PartialEq, Eq)]
pub enum NavigationState {
    Menu,
    Texting,
    ContactManagement,
}

/// Represents the events that can occur in the application. These are used to update the model.
pub enum EventMessage {
    InputCharacter(char),
    DeleteCharacter,
    Up,
    Down,
    SelectContact,
    SendMessageSuccess,
    SendMessageFailure,
    SendContactRequest,
    AcceptContactRequest,
    DeclineContactRequest,
    ToContactRequests,
    ToTexting,
    ToMenu,
    ToggleFocus,
    Quit,
}

/// Represents the userdata file.
#[derive(Serialize, Deserialize)]
pub struct UserData {
    pub username: String,
    pub priv_dsa: String,
}
