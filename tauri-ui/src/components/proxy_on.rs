use stylist::yew::use_style;
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
    let ondelete = {
        let trigger = trigger.clone();
        let requests = requests.clone();
        Callback::from(move |id: usize| {
            let mut r = requests.borrow_mut();
            r.remove(id);
            trigger.force_update();
        })
    };
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
    let style = use_style!(
        r#"
        display: flex;
        flex-flow: column;
        align-items: center;
        vertical-align: baseline;
        overflow: auto;
        * {
            margin: 0.5em;
        }
        div:first-child button {
            font-size: 2em;
            width: 5em;
        }
        .request-table {
            flex: 1;
            align-self: stretch;
            white-space: nowrap;
            min-height: min-content;
            display: block;
            overflow-y: scroll;
        }
        .request-table,
        .request-table th,
        .request-table td {
            border: 1px solid var(--font-color);
            border-collapse: collapse;
        }
        .request-table th {
            text-align: left;
            padding: 0.5em;
        }
        .request-table tr > td:first-child {
            width: 100%
        }
        .request-table td {
           padding: 0.5em;
        }
        .request-table tr:first-child {
            position: sticky;
            top: 0;
            background-color: var(--bg-color);
            border: 1px solid var(--font-color);
            z-index: 1000;
        }
        "#
    );
    html! {
        <div class={style}>
            <div >
                <button
                    onclick={Callback::from(move |_| paused.set(!*paused))}
                    ~innerText={ if *paused {"▶"} else {"⏸"} }/>
                <button {onclick} ~innerText={"⏹"} />
            </div>
            if requests.borrow().len() > 0 {
                <table class="request-table">
                    <RequestHeader />
                    {
                        requests.borrow().iter().cloned().enumerate().map(
                            |(id, exchange)| {
                                let ondelete = ondelete.clone();
                                let ondelete = Callback::from(move |()| {
                                    ondelete.emit(id);
                                });
                                html!{
                                    <RequestRow {ondelete} {exchange}/>
                                }
                            }
                        ).collect::<Html>()
                    }
                </table>
            } else {
                <h3 class="request-not-found">{"No Request Yet!"}</h3>
            }
        </div>
    }
}
