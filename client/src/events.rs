use crate::*;
use crossterm::event::KeyCode;
use crossterm::event::{self, Event};
use lib::Result;
use std::time::Duration;
use tokio::net::tcp::OwnedWriteHalf;

// Handles the application event based on the key code and the current model state
pub async fn handle_event(
    model: &Model,
    writer: &mut OwnedWriteHalf,
) -> Result<Option<EventMessage>> {
    if event::poll(Duration::from_millis(25))? {
        if let Event::Key(key) = event::read()? {
            match model.navigation_state {
                NavigationState::Menu => return Ok(handle_menu_event(key.code, model)),
                NavigationState::Texting => {
                    return Ok(handle_texting_event(key.code, model, writer).await)
                }
                NavigationState::ContactManagement => {
                    return Ok(handle_contact_management_event(key.code, model, writer).await)
                }
            }
        }
    }
    Ok(None)
}

fn handle_menu_event(key_code: KeyCode, _model: &Model) -> Option<EventMessage> {
    match key_code {
        KeyCode::Enter => Some(EventMessage::SelectContact),
        KeyCode::Up => Some(EventMessage::Up),
        KeyCode::Down => Some(EventMessage::Down),
        KeyCode::Char('q') => Some(EventMessage::Quit),
        KeyCode::Char('f') => Some(EventMessage::ToContactRequests),
        _ => None,
    }
}

async fn handle_texting_event(
    key_code: KeyCode,
    model: &Model,
    writer: &mut OwnedWriteHalf,
) -> Option<EventMessage> {
    match key_code {
        KeyCode::Char(c) => {
            if model.focus == Focus::Input {
                Some(EventMessage::InputCharacter(c))
            } else {
                None
            }
        }
        KeyCode::Backspace => Some(EventMessage::DeleteCharacter),
        KeyCode::Esc => Some(EventMessage::ToMenu),
        KeyCode::Enter => match chat_logic::send_message(&model, writer).await {
            Ok(_) => {
                info!("Message sent");
                Some(EventMessage::SendMessageSuccess)
            }
            Err(e) => {
                error!("Failed to send message. Error: {}", e);
                Some(EventMessage::SendMessageFailure)
            }
        },
        _ => None,
    }
}

async fn handle_contact_management_event(
    key_code: KeyCode,
    model: &Model,
    writer: &mut OwnedWriteHalf,
) -> Option<EventMessage> {
    match key_code {
        KeyCode::Char(c) => {
            if model.focus == Focus::Input {
                Some(EventMessage::InputCharacter(c))
            } else {
                if c == 'x' {
                    decline_contact_request(&model);
                    Some(EventMessage::DeclineContactRequest)
                } else {
                    None
                }
            }
        }
        KeyCode::Backspace => Some(EventMessage::DeleteCharacter),
        KeyCode::Enter => {
            if model.focus == Focus::Input {
                if model.input.is_empty() || model.input == model.username {
                    return None;
                }

                send_contact_request(&model, writer).await;
                Some(EventMessage::SendContactRequest)
            } else if model.focus == Focus::List {
                accept_contact_request(&model).await;
                Some(EventMessage::AcceptContactRequest)
            } else {
                None
            }
        }
        KeyCode::Esc => Some(EventMessage::ToMenu),
        KeyCode::Up => {
            if model.focus == Focus::List {
                Some(EventMessage::Up)
            } else {
                None
            }
        }
        KeyCode::Down => {
            if model.focus == Focus::List {
                Some(EventMessage::Down)
            } else {
                None
            }
        }
        KeyCode::Tab => Some(EventMessage::ToggleFocus),
        _ => None,
    }
}
