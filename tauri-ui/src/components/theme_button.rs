use yew::prelude::*;

#[function_component(ThemeButton)]
pub fn theme_button() -> Html {
    let is_dark = use_state(|| {
        let mut is_dark = false;
        if let Some(window) = web_sys::window() {
            if let Ok(Some(media)) = window.match_media("(prefers-color-scheme: dark)") {
                is_dark = media.matches();
            }
        }
        is_dark
    });

    let (data_theme, btn_text) = if *is_dark {
        ("dark", "🔆")
    } else {
        ("light", "🌙")
    };
    if let Some(window) = web_sys::window() {
        if let Some(document) = window.document() {
            if let Some(body) = document.body() {
                body.set_attribute("data-theme", data_theme).unwrap();
            }
        }
    }

    let onclick = {
        let is_dark = is_dark;
        Callback::from(move |_| is_dark.set(!*is_dark))
    };
    html! {
        <button {onclick} ~innerText={btn_text} />
    }
}
