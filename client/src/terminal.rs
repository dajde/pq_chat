use crate::Result;
use crossterm::{
    cursor::SavePosition,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::prelude::*;
use std::{io::stdout, panic};

// Enables raw mode and enters the alternate screen
pub fn init_terminal() -> Result<Terminal<impl Backend>> {
    stdout().execute(SavePosition)?;
    install_panic_hook();
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    Ok(terminal)
}

// Installs a panic hook that restores the terminal state before panicking
pub fn install_panic_hook() {
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        stdout().execute(LeaveAlternateScreen).unwrap();
        disable_raw_mode().unwrap();
        original_hook(panic_info);
    }));
}

#[macro_export]
macro_rules! exit_app {
    ($msg:expr $(, $arg:expr)*) => {{
        stdout().execute(LeaveAlternateScreen).unwrap();
        disable_raw_mode().unwrap();
        stdout().execute(cursor::Show).unwrap();
        println!($msg $(, $arg)*);
        exit(1);
    }};
}
