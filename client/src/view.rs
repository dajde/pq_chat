use crate::Focus;
use crate::Model;
use crate::NavigationState;
use ratatui::{prelude::*, widgets::*};
use std::time::{Duration, UNIX_EPOCH};

// Renders the application view based on the model state
pub fn view(model: &Model, f: &mut Frame) {
    f.render_widget(Clear, f.size());

    match model.navigation_state {
        NavigationState::Menu => menu_view(f, model),
        NavigationState::Texting => texting_view(f, model),
        NavigationState::ContactManagement => contacts_view(f, model),
    }
}

fn menu_view(f: &mut Frame, model: &Model) {
    let vertical = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ]);

    let [title_area, contacts_area, hint_area] = vertical.areas(f.size());

    let contacts: Vec<ListItem> = model
        .contacts
        .iter()
        .enumerate()
        .map(|(i, name)| {
            ListItem::new(name.to_string()).style(if model.list_selected == i {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            })
        })
        .collect();

    let contacts_list = List::new(contacts).block(Block::default().borders(Borders::ALL));

    f.render_widget(
        Span::styled(
            [model.username.as_str(), "Contacts"].join(" ─── "),
            Style::new().light_green().bold(),
        ),
        title_area,
    );
    f.render_widget(contacts_list, contacts_area);
    f.render_widget(
        hint_bar(&[
            ("↑", "Up"),
            ("↓", "Down"),
            ("Enter", "Select"),
            ("F", "Contacts"),
            ("Q", "Quit"),
        ]),
        hint_area,
    );
}

fn texting_view(f: &mut Frame, model: &Model) {
    let vertical = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(3),
        Constraint::Length(1),
    ]);

    let [title_area, messages_area, input_area, hint_area] = vertical.areas(f.size());

    let title = Span::styled(
        [
            model.username.as_str(),
            &["Chat", model.recipient.as_str()].join(" with "),
        ]
        .join(" ─── "),
        Style::new().light_green().bold(),
    );

    let conversation = model
        .conversations
        .iter()
        .find(|conv| conv.recipient == model.recipient)
        .unwrap();

    let texts = conversation
        .messages
        .iter()
        .map(|msg| {
            let sender = if msg.sender == model.username {
                "You"
            } else {
                msg.sender.as_str()
            };

            let duration = Duration::from_secs(msg.timestamp.try_into().unwrap());
            let datetime = UNIX_EPOCH + duration;

            let datetime_formatted = chrono::DateTime::<chrono::Utc>::from(datetime)
                .with_timezone(&chrono::Local)
                .format("%H:%M:%S");

            Line::from(format!(
                "{} {}: {}",
                datetime_formatted, sender, msg.message
            ))
        })
        .collect::<Vec<Line>>();

    let messages_capacity: u16 = messages_area.height - 2;

    let scroll: (u16, u16) = if texts.len() as u16 > messages_capacity {
        (texts.len() as u16 - messages_capacity, 0)
    } else {
        (0, 0)
    };

    let messages = Paragraph::new(texts)
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::ALL))
        .scroll(scroll)
        .wrap(Wrap { trim: true });

    let input_capacity: u16 = input_area.width - 2;

    let input_scroll = if model.input.len() as u16 > input_capacity {
        model.input.len() as u16 - input_capacity
    } else {
        0
    };

    let input = Paragraph::new(model.input.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL))
        .scroll((0, input_scroll));

    f.render_widget(title, title_area);
    f.render_widget(messages, messages_area);
    f.render_widget(input, input_area);
    f.render_widget(
        hint_bar(&[("Enter", "Send message"), ("ESC", "To menu")]),
        hint_area,
    );
}

fn contacts_view(f: &mut Frame, model: &Model) {
    let vertical = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(3),
        Constraint::Length(1),
    ]);

    let [title_area, requests_area, input_area, hint_area] = vertical.areas(f.size());

    let title = Span::styled(
        [model.username.as_str(), "Contacts management"].join(" ─── "),
        Style::new().light_green().bold(),
    );

    let requests: Vec<ListItem> = model
        .contact_requests
        .iter()
        .enumerate()
        .map(|(i, name)| {
            ListItem::new(name.to_string()).style(
                if model.list_selected == i && model.focus == Focus::List {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                },
            )
        })
        .collect();

    let requests_list_widget = List::new(requests).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Pending requests"),
    );

    let input = Paragraph::new(model.input.as_str())
        .style(if model.focus == Focus::Input {
            Style::new().fg(Color::Yellow)
        } else {
            Style::default()
        })
        .block(Block::new().borders(Borders::ALL));

    let hint_bar = match model.focus {
        Focus::Input => hint_bar(&[
            ("Enter", "Send request"),
            ("TAB", "Change focus"),
            ("ESC", "To menu"),
        ]),
        Focus::List => hint_bar(&[
            ("↑", "Up"),
            ("↓", "Down"),
            ("Enter", "Accept"),
            ("X", "Decline"),
            ("TAB", "Change focus"),
            ("ESC", "To menu"),
        ]),
    };

    f.render_widget(title, title_area);
    f.render_widget(requests_list_widget, requests_area);
    f.render_widget(input, input_area);
    f.render_widget(hint_bar, hint_area);
}

fn hint_bar(keys: &[(&str, &str)]) -> Line<'static> {
    let bottom_bar: Vec<_> = keys
        .iter()
        .flat_map(|(key, desc)| {
            let key = Span::styled(format!(" {key} "), Style::new().dark_gray().on_black());
            let desc = Span::styled(format!(" {desc} "), Style::new().black().on_dark_gray());
            [key, desc]
        })
        .collect();

    Line::from(bottom_bar).centered()
}
