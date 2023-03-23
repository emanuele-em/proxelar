use gloo_timers::callback::Timeout;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo_utils::format::JsValueSerdeExt;
use yew::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window.__TAURI__.tauri"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;
}
#[derive(Serialize, Deserialize)]
struct Start {
    addr: SocketAddr,
}

#[function_component(App)]
pub fn app() -> Html {
    let proxy_state = use_state(|| false);
    let request_count = use_state(|| 0);
    let onclick = {
        let proxy_state = proxy_state.clone();
        let requests_count = request_count.clone();
        {
            let request_count = request_count.clone();
            let proxy_state = proxy_state.clone();
            Timeout::new(1_000, move || {
                spawn_local(async move {
                    let mut count = *request_count;
                    if *proxy_state {
                       let value= invoke("plugin:proxy|fetch_request", JsValue::NULL).await;
                       if !value.is_falsy() {
                           count +=1;
                       }
                       request_count.set(count);
                    }
                }
                )
            })
            .forget();
        };

        Callback::from(move |_| {
            if *proxy_state {
                spawn_local(async move {
                   invoke("plugin:proxy|stop_proxy", JsValue::NULL).await;
                });
                requests_count.set(0);
            } else {
                let args = JsValue::from_serde(&Start {
                    addr: "127.0.0.1:8100".parse().unwrap(),
                })
                .unwrap();
                spawn_local(async move {
                   invoke("plugin:proxy|start_proxy", args).await;
                });
            };
            proxy_state.set(!*proxy_state);
        })
    };
    html! {
        <main>
            <h1>{"Man In The Middle Proxy"}</h1>
            <button {onclick}>{if *proxy_state {"On"} else {"Off"} }</button>
            if *proxy_state {
                <p>{*request_count}</p>
            }
        </main>
    }
}
