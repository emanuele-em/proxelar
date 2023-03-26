use stylist::yew::use_style;
use yew::prelude::*;

use crate::api::fetch_proxy_status;
use crate::components::proxy_off::ProxyOff;
use crate::components::proxy_on::ProxyOn;
use crate::components::title_bar::TitleBar;

#[function_component(App)]
pub fn app() -> Html {
    let proxy_state = use_state(|| false);
    {
        let proxy_state = proxy_state.clone();
        use_effect_with_deps(
            move |_| fetch_proxy_status(Callback::from(move |status| proxy_state.set(status))),
            (),
        )
    };
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
    let style = use_style!(
        r#"
        display: flex;
        height: 100vh;
        flex-flow: column;
        > :last-child {
            flex: 1;
        }
        "#
    );
    html! {
        <main class={style}>
            <TitleBar />
            if *proxy_state {
                <ProxyOn {stop} />
            } else {
                <ProxyOff {start} />
            }
        </main>
    }
}
