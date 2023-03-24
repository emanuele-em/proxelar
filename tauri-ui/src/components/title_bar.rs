use stylist::yew::use_style;
use yew::prelude::*;

#[function_component(ThemeButton)]
fn theme_button() -> Html {
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

#[function_component(TitleBar)]
pub fn title_bar() -> Html {
    let style = use_style!(
        r#"
        display: flex;
        flex-flow: row;
        align-items: center;
        vertical-align: baseline;
        h1 {
            flex: 1;
        }
        button {
        }
        * {
           font-size: 2rem;
           margin: 0.5rem;
        }
        "#
    );
    html! {
        <div class={style}>
            <h1 ~innerText="Man In The Middle Proxy" />
            <ThemeButton />
        </div>
    }
}
