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

    let (data_theme, btn_text) = match *is_dark {
        true => ("dark", "🔆"),
        false => ("light", "🌙"),
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
        justify-content:space-between;
        position: relative;
        h1{
            right:0;
            left:0;
            text-align:center;
            font-size: 1.2rem;
            font-weight: normal;
            flex: none;
            margin:auto;
            text-transform: uppercase;
            font-size: 1rem;
            font-weight: bold;
            position:absolute;
            margin:auto;
            z-index:-1;
        }
        button{
            background: var(--bg-input);
            border: 0px;
            width:45px;
            text-align:center;
            height: 45px;
            line-height:42px;
            border-radius: 100px; 
            color: white;
            box-shadow: var(--box-shadow);
            margin-left:auto;
            text-shadow: 2px 2px 8px #00000033; 
            cursor:pointer;
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
