use crate::api::{poll_proxy, stop_proxy};
use gloo_timers::callback::Timeout;
use proxyapi_models::RequestInfo;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub stop: Callback<()>,
}

#[function_component(ProxyOn)]
pub fn proxy_on(props: &Props) -> Html {
    let trigger = use_force_update();
    let requests = use_mut_ref(Vec::<RequestInfo>::new);
    {
        let requests = requests.clone();
        Timeout::new(1_000, move || {
            spawn_local(async move {
                let on_request = Callback::from(move |request_info| {
                    let mut r = requests.borrow_mut();
                    r.push(request_info);
                });
                poll_proxy(Some(on_request));
                trigger.force_update();
            })
        })
        .forget();
    };
    let onclick = {
        let requests = requests.clone();
        let stop = props.stop.clone();
        Callback::from(move |_| {
            let requests = requests.clone();
            let stop = stop.clone();
            let on_stop = Callback::from(move |_: ()| {
                let mut r = requests.borrow_mut();
                r.drain(..);
                stop.emit(());
            });
            stop_proxy(Some(on_stop));
        })
    };
    html! {
        <>
            <button {onclick} ~innerText={"Stop Proxy"} />
            {
                requests.borrow().iter().filter_map(|r| {
                    r.0.as_ref().map(|r| html!{<li>{r.method().to_string()}</li>})
                }).collect::<Html>()
            }
        </>
    }
}
