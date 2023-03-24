use yew::prelude::*;

use crate::api::{listen_proxy_event, stop_proxy};
use crate::components::request::{RequestHeader, RequestRow};

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub stop: Callback<()>,
}

#[function_component(ProxyOn)]
pub fn proxy_on(props: &Props) -> Html {
    let trigger = use_force_update();
    let paused = use_state(|| false);
    let requests = use_mut_ref(Vec::new);
    use_effect_with_deps(
        move |(requests, paused)| {
            let requests = requests.clone();
            let paused = *paused;
            let on_request = Callback::from(move |request_info| {
                let mut r = requests.borrow_mut();
                if !paused {
                    r.push(request_info);
                    trigger.force_update();
                }
            });
            let listener = listen_proxy_event(Some(on_request));
            move || drop(listener)
        },
        (requests.clone(), *paused),
    );
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
        <div class="proxy-on">
            <div class="play-pause-stop">
                if *paused {
                    <button onclick={Callback::from(move |_| paused.set(false))} ~innerText="▶" />
                } else {
                    <button onclick={Callback::from(move |_| paused.set(true))} ~innerText="⏸" />
                }
                <button {onclick} ~innerText={"⏹"} />
            </div>
            if requests.borrow().len() > 0 {
                <table class="request-table">
                    <RequestHeader />
                    {
                        requests.borrow().iter().cloned().map(
                            |exchange| html!{ <RequestRow {exchange}/> }
                        ).collect::<Html>()
                    }
                </table>
            } else {
                <h3 class="request-not-found">{"No Request Yet!"}</h3>
            }
        </div>
    }
}
