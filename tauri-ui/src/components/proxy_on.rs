use gloo_timers::callback::Timeout;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::api::{poll_proxy, stop_proxy};
use crate::components::request::{RequestRow, RequestHeader};

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub stop: Callback<()>,
}

#[function_component(ProxyOn)]
pub fn proxy_on(props: &Props) -> Html {
    let trigger = use_force_update();
    let paused = use_state(|| false);
    let requests = use_mut_ref(Vec::new);
    {
        let requests = requests.clone();
        let paused = paused.clone();
        Timeout::new(1_000, move || {
            spawn_local(async move {
                let on_request = Callback::from(move |request_info| {
                    let mut r = requests.borrow_mut();
                    if !*paused {
                        r.push(request_info);
                    }
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
            if *paused {
                <button onclick={Callback::from(move |_| paused.set(false))} ~innerText="Play" />
            } else {
                <button onclick={Callback::from(move |_| paused.set(true))} ~innerText="Pause" />
            }
            <button class="stop" {onclick} ~innerText={"Stop Proxy"} />
            if requests.borrow().len() > 0 {
                <table>
                    <RequestHeader />
                    {
                        requests.borrow().iter().cloned().map(
                            |exchange| html!{ <RequestRow {exchange}/> }
                        ).collect::<Html>()
                    }
                </table>
            } else {
                <h3>{"No Request Yet!"}</h3>
            }
        </>
    }
}
