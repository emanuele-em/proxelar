mod details;
mod row;

use self::details::RequestDetails;
use self::row::RequestRow;
use crate::api::listen_proxy_event;
use proxyapi_models::RequestInfo;
use std::{cell::RefCell, rc::Rc};
use stylist::yew::use_style;
use yew::prelude::*;

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
    let ondeselect = {
        let selected = selected.clone();
        Callback::from(move |()| selected.set(None))
    };
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
                    <tr>
                        <th ~innerText="Path"/>
                        <th ~innerText="Method"/>
                        <th ~innerText="Status"/>
                        <th ~innerText="Size"/>
                        <th ~innerText="Time"/>
                        <th ~innerText="Action"/>
                    </tr>
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
                    if let Some(RequestInfo(Some(req), Some(res))) = requests.borrow().iter().nth(idx) {
                        <RequestDetails {ondeselect} response={res.clone()} request={req.clone()} />
                    }
                }
            </div>
        } else {
            <h3 ~innerText="No Request Yet!" />
        }
    }
}
