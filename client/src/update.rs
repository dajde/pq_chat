use crate::*;
use lib::sql::*;

// Updates the model based on the event message
pub fn update_model(model: &mut Model, msg: EventMessage) -> Option<EventMessage> {
    match msg {
        EventMessage::Quit => {
            model.running_state = RunningState::Done;
        }
        EventMessage::InputCharacter(c) => {
            if model.focus == Focus::Input {
                model.input.push(c)
            }
        }
        EventMessage::DeleteCharacter => {
            model.input.pop();
        }
        EventMessage::ToTexting => {
            model.navigation_state = NavigationState::Texting;
            model.focus = Focus::Input;
        }
        EventMessage::ToMenu => {
            model.list_selected = 0;
            model.focus = Focus::List;
            model.navigation_state = NavigationState::Menu;
        }
        EventMessage::Up => match model.navigation_state {
            NavigationState::Menu => {
                if model.contacts.is_empty() {
                    return None;
                };

                if model.list_selected > 0 {
                    model.list_selected -= 1;
                }
            }
            NavigationState::ContactManagement => {
                if model.contact_requests.is_empty() {
                    return None;
                };

                if model.list_selected > 0 {
                    model.list_selected -= 1;
                }
            }
            _ => {}
        },
        EventMessage::Down => match model.navigation_state {
            NavigationState::Menu => {
                if model.contacts.is_empty() {
                    return None;
                };

                if model.list_selected < model.contacts.len() - 1 {
                    model.list_selected += 1;
                }
            }
            NavigationState::ContactManagement => {
                if model.contact_requests.is_empty() {
                    return None;
                };

                if model.list_selected < model.contact_requests.len() - 1 {
                    model.list_selected += 1;
                }
            }
            _ => {}
        },
        EventMessage::ToggleFocus => {
            if model.focus == Focus::List {
                model.focus = Focus::Input;
            } else {
                model.focus = Focus::List;
            }
        }
        EventMessage::SelectContact => {
            if model.contacts.is_empty() {
                return None;
            }

            model.recipient = model.contacts[model.list_selected].clone();
            model.input = String::new();
            return Some(EventMessage::ToTexting);
        }
        EventMessage::ToContactRequests => {
            model.focus = Focus::Input;
            model.list_selected = 0;
            let contact_requests = get_contact_requests().unwrap();
            model.contact_requests = contact_requests;
            model.navigation_state = NavigationState::ContactManagement;
        }
        EventMessage::SendContactRequest => {
            update_contacts(model);
            model.input = String::new();
        }
        EventMessage::SendMessageSuccess => {
            model
                .conversations
                .iter_mut()
                .find(|conv| conv.recipient == model.recipient)
                .unwrap()
                .messages
                .push(ConversationMessage {
                    sender: model.username.clone(),
                    message: model.input.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                });

            model.input = String::new();
        }
        EventMessage::SendMessageFailure => {
            model
                .conversations
                .iter_mut()
                .find(|conv| conv.recipient == model.recipient)
                .unwrap()
                .messages
                .push(ConversationMessage {
                    sender: model.username.clone(),
                    message: "Failed to send message. Check log for more information".to_string(),
                    timestamp: chrono::Utc::now().timestamp(),
                });

            model.input = String::new();
        }

        EventMessage::AcceptContactRequest => {
            update_contacts(model);
        }
        EventMessage::DeclineContactRequest => {
            update_contacts(model);
        }
    };
    None
}

fn update_contacts(model: &mut Model) {
    let requests = get_contact_requests().unwrap();
    let contacts = get_contacts().unwrap();
    let conversations: Vec<Conversation> = contacts
        .iter()
        .map(|contact| Conversation {
            recipient: contact.clone(),
            messages: vec![],
        })
        .collect();

    model.contact_requests = requests;
    model.contacts = contacts;
    model.conversations = conversations;
}
