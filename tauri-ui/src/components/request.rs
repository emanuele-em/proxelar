use std::{cell::RefCell, rc::Rc};
use stylist::yew::use_style;

use crate::api::listen_proxy_event;
use proxyapi_models::RequestInfo;
use yew::prelude::*;
#[derive(Clone, PartialEq, Properties)]
struct RowProps {
    pub exchange: RequestInfo,
    pub idx: usize,
    pub ondelete: Callback<usize>,
    pub onselect: Callback<usize>,
}

#[function_component(RequestHeader)]
fn request_header() -> Html {
    html! {
        <tr>
            <th ~innerText="Path"/>
            <th ~innerText="Method"/>
            <th ~innerText="Status"/>
            <th ~innerText="Size"/>
            <th ~innerText="Time"/>
            <th ~innerText="Action"/>
        </tr>
    }
}

#[function_component(RequestRow)]
fn request_row(props: &RowProps) -> Html {
    match props.exchange {
        RequestInfo(Some(ref req), Some(ref res)) => {
            let idx = props.idx;
            let method = req.method().to_string();
            let ondelete = props.ondelete.clone();
            let onselect = props.onselect.clone();
            html! {
                <tr onclick={move |_| {onselect.emit(idx)}}>
                    <td>{req.uri().to_string()}</td>
                    <td class={classes!("method", &method)} >{method}</td>
                    <td>{res.status().to_string()}</td>
                    <td>{req.body().len()}</td>
                    <td>{((res.time() - req.time()) as f64 * 1e-6).trunc()}</td>
                    <td>
                        <button
                            onclick={move |e: MouseEvent| {ondelete.emit(idx); e.stop_immediate_propagation();}}
                            ~innerText="🗑 "/>
                    </td>
                </tr>
            }
        }
        _ => {
            html! {
                <tr>{"Parsing Falied"}</tr>
            }
        }
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub requests: Rc<RefCell<Vec<RequestInfo>>>,
    pub paused: bool,
}

#[function_component(RequestTable)]
pub fn request_table(props: &Props) -> Html {
    let trigger = use_force_update();
    let requests = props.requests.clone();
    let paused = props.paused;
    let selected = use_state_eq(|| None as Option<usize>);
    let onselect = {
        let requests = requests.clone();
        let selected = selected.clone();
        Callback::from(move |id: usize| {
            let len = requests.borrow().len();
            if id < len {
                selected.set(Some(id));
            }
        })
    };
    let ondelete = {
        let requests = requests.clone();
        let trigger = trigger.clone();
        let selected = selected.clone();
        Callback::from(move |id: usize| {
            let mut r = requests.borrow_mut();
            r.remove(id);
            match *selected {
                Some(cur) if cur == id => {
                    selected.set(None);
                }
                Some(cur) if cur > id => {
                    selected.set(Some(cur - 1));
                }
                _ => {}
            }
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
        (requests.clone(), paused),
    );
    let style = use_style!(
        r#"
        display: flex;
        flex-flow: row;
        width: 100%;
        vertical-align: baseline;
        overflow-y: hidden;
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
            border-spacing: 0;
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
            z-index: 1000;
        }
        .request {
            flex: 1;
        }
        "#
    );
    html! {
        if requests.borrow().len() > 0 {
            <div class={style}>
                <table class="request-table">
                    <RequestHeader />
                    {
                        requests.borrow().iter().cloned().enumerate().map(
                            |(idx, exchange)| {
                                let ondelete = ondelete.clone();
                                let onselect = onselect.clone();
                                html!{
                                    <RequestRow {onselect} {idx} {ondelete} {exchange}/>
                                }
                            }
                        ).collect::<Html>()
                    }
                </table>
                if let Some(idx) = *selected {
                    if let Some(RequestInfo(Some(req), Some( res))) = requests.borrow().iter().nth(idx) {
                        <div class="request">
                            {format!("{:?}{:?}", req, res)}
                        </div>
                    }
                }
            </div>
        } else {
            <h3 ~innerText="No Request Yet!" />
        }
    }
}
