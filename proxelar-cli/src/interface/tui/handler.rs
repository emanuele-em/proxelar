use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::state::AppState;

/// Handle a key event. Returns true if the app should quit.
pub fn handle_key_event(key: KeyEvent, state: &mut AppState) -> bool {
    // Filter mode: capture text input
    if state.filter_mode {
        match key.code {
            KeyCode::Esc => {
                state.filter_mode = false;
                state.filter_input.clear();
                state.filter = None;
            }
            KeyCode::Enter => {
                state.filter_mode = false;
                if state.filter_input.is_empty() {
                    state.filter = None;
                } else {
                    state.filter = Some(state.filter_input.clone());
                }
            }
            KeyCode::Backspace => {
                state.filter_input.pop();
            }
            KeyCode::Char(c) => {
                state.filter_input.push(c);
            }
            _ => {}
        }
        return false;
    }

    match key.code {
        KeyCode::Char('q' | 'Q') => return true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
        KeyCode::Char('j') | KeyCode::Down => state.select_next(),
        KeyCode::Char('k') | KeyCode::Up => state.select_prev(),
        KeyCode::Char('g') => state.select_first(),
        KeyCode::Char('G') => state.select_last(),
        KeyCode::Enter => state.toggle_detail(),
        KeyCode::Tab => state.toggle_tab(),
        KeyCode::Char('/') => {
            state.filter_mode = true;
            state.filter_input.clear();
        }
        KeyCode::Esc => {
            if state.detail_open {
                state.detail_open = false;
            } else {
                state.filter = None;
            }
        }
        KeyCode::Char('c') => state.clear(),
        _ => {}
    }

    false
}
