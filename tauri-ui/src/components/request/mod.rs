mod details;
mod request_tab;
mod response_tab;
mod row;
mod tab_view;

const OPTIONS: [&str; 10] = [
    "POST", "GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE", "OTHERS",
];

use self::details::RequestDetails;
use self::row::RequestRow;
use crate::api::listen_proxy_event;
use crate::components::input::MultipleSelectInput;
use proxyapi_models::RequestInfo;
use std::{cell::RefCell, rc::Rc};
use stylist::yew::use_style;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub requests: Rc<RefCell<Vec<RequestInfo>>>,
    pub paused: bool,
}

pub fn filter_request(method: String, filters: &[String]) -> bool {
    filters.contains(&method)
        || (!OPTIONS.contains(&method.as_str()) && filters.contains(&"OTHERS".to_string()))
}

#[function_component(RequestTable)]
pub fn request_table(props: &Props) -> Html {
    let options = OPTIONS.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let trigger = use_force_update();
    let requests = props.requests.clone();
    let paused = props.paused;
    let selected = use_state_eq(|| None as Option<usize>);
    let filters = use_state_eq(|| options.clone());
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
    let onfilterchange = {
        let filters = filters.clone();
        let requests = requests.clone();
        let selected = selected.clone();
        Callback::from(move |new_value: Vec<String>| {
            if let Some(idx) = *selected {
                if let Some(RequestInfo(Some(req), _)) = requests.borrow().get(idx) {
                    if !filter_request(req.method().to_string(), &new_value) {
                        selected.set(None);
                    }
                }
            }
            filters.set(new_value)
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
        width: 100%;
        overflow-y: auto;
        padding-bottom: 80px;
        
        .request-table{
            width: 95%;
            margin:25px auto;
            max-height: 100%;
            border-collapse: collapse;
            table-layout: fixed;
            color: var(--font-color);
            border-radius: 10px;
            box-shadow: var(--box-shadow);
            overflow:hidden;
        }
        .request-table tr
        {
            border-bottom: 1px solid var(--little-contrast);
            background: var(--bg-color-secondary);
            font-size:0.8rem;
            cursor: pointer;
            margin-top: 5px;
            margin-bottom: 5px;
        }
        .request-table td{
            max-width: 50px;
        }
        .request-table td:first-child,
        .request-table th:first-child{
            overflow:hidden;
            white-space: nowrap;
        }
        .request-table td,
        .request-table th,
        {
           padding: 5px 10px;
           white-space: nowrap;
           overflow:hidden;
           width: 100px;
           text-overflow: ellipsis;
           text-align: left;
        }

        .request-table th{
            padding: 10px;
        }
        .request-table tr td:first-child,
        .request-table tr th:first-child
        {
            width: 100%;
            min-width:100%;
        }
        .request-table tr td:last-child,
        .request-table tr th:last-child
        {
            text-align:center;
        }
        .request-table tr:first-child {
            position: sticky;
            top: 0;
            z-index: 1000;
            padding: 10px auto;
            width:100%;
        }
        "#
    );
    let method_filter_style = use_style!(
        r#"
        position: relative;
        select {
            height: 100%;
            display: none;
            position: absolute;
            min-height: 13em;
            overflow: visible;
            z-index: 1;
        }
        :hover > select {display: block;}
        "#
    );
    let loader = use_style!(
        r#"
            position: absolute;
            top:0;
            bottom:0;
            margin:auto;
            width:  48px;
            height: 48px;
            background: var(--gradient);
            transform: rotateX(65deg) rotate(45deg);
            transform: perspective(200px) rotateX(65deg) rotate(45deg); 
            color: var(--loader-color);
            animation: layers1 1s linear infinite alternate;

        :after {
            content: '';
            position: absolute;
            inset: 0;
            background: var(--bg-input);
            opacity:.9;
            animation: layerTr 1s linear infinite alternate;
        }

        @keyframes layers1 {
            0% { box-shadow: 0px 0px 0 0px  var(--bg-color-secondary)}
            90% , 100% { box-shadow: 20px 20px 0 -4px var(--bg-color-secondary)}
        }
        @keyframes layerTr {
            0% { transform:  translate(0, 0) scale(1) }
            100% {  transform: translate(-25px, -25px) scale(1) }
        }
    "#
    );

    html! {
        if requests.borrow().len() > 0 {
            <div class={style}>
                <table class="request-table">
                    <tr>
                        <th ~innerText="Path"/>
                        <th class={method_filter_style}>
                            <span ~innerText={"Method ↓"} />
                            <MultipleSelectInput {options} onchange={onfilterchange} />
                        </th>
                        <th ~innerText="Status"/>
                        <th ~innerText="Size"/>
                        <th ~innerText="Time"/>
                        <th ~innerText="Action"/>
                    </tr>
                    {
                        requests.borrow().iter().cloned().enumerate().filter_map(
                            |(idx, exchange)| {
                                let ondelete = ondelete.clone();
                                let onselect = onselect.clone();
                                if let Some(ref req) = exchange.0{
                                    if filter_request(req.method().to_string(), &filters) {
                                        return Some(html!{
                                            <RequestRow {onselect} {idx} {ondelete} {exchange}/>
                                        })
                                    }
                                }
                                None
                            }
                        ).collect::<Html>()
                    }
                </table>
                if let Some(idx) = *selected {
                    if let Some(RequestInfo(Some(req), Some(res))) = requests.borrow().get(idx) {
                        <RequestDetails {ondeselect} response={res.clone()} request={req.clone()} />
                    }
                }
            </div>
        } else {
            <span class={loader}></span>
        }
    }
}
