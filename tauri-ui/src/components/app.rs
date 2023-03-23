use yew::prelude::*;

use crate::components::proxy_off::ProxyOff;
use crate::components::proxy_on::ProxyOn;
use crate::components::theme_button::ThemeButton;

#[function_component(App)]
pub fn app() -> Html {
    let proxy_state = use_state(|| false);
    let start = {
        let proxy_state = proxy_state.clone();
        Callback::from(move |_: ()| {
            proxy_state.set(true);
        })
    };
    let stop = {
        let proxy_state = proxy_state.clone();
        Callback::from(move |_: ()| {
            proxy_state.set(false);
        })
    };
    html! {
        <main>
            <div class="title">
                <h1>{"Man In The Middle Proxy"}</h1>
                <ThemeButton />
            </div>
            if *proxy_state {
                <ProxyOn {stop} />
            } else {
                <ProxyOff {start} />
            }
        </main>
    }
}
