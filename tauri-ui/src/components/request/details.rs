use proxyapi_models::{ProxiedRequest, ProxiedResponse};
use stylist::yew::use_style;
use yew::prelude::*;
#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub request: ProxiedRequest,
    pub response: ProxiedResponse,
    pub ondeselect: Callback<()>,
}

#[derive(Clone, PartialEq, Properties)]
pub struct RequestProps {
    pub request: ProxiedRequest,
}

#[function_component(Request)]
pub fn request(props: &RequestProps) -> Html {
    let req = props.request.clone();
    html! {
        {format!("{:?}", req)}
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct ResponeProps {
    pub response: ProxiedResponse,
}

#[function_component(Response)]
pub fn response(props: &ResponeProps) -> Html {
    let res = props.response.clone();
    html! {
        {format!("{:?}", res)}
    }
}

#[derive(Default, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Request,
    Response,
}

#[function_component(RequestDetails)]
pub fn request_details(props: &Props) -> Html {
    let style = use_style!(
        r#"
        display: flex;
        flex-flow: column;
        flex: 1;
        div {
            display: flex;
            flex-flow: row;
        }
        button {
            margin: 0;
            min-width: fit-content;
            padding: 0 .5rem;
        }
        div > button:last-child {
            width: 2rem;
            margin-left: auto;
            align-self: flex-end;
        }
        .tab_selected {
            border: 2px solid var(--font-color);
            background-color: var(--bg-color);
        }
        "#
    );
    let tab = use_state_eq(Tab::default);
    let ontabchange = {
        let tab = tab.clone();
        Callback::from(move |tab_selected| tab.set(tab_selected))
    };
    let req = props.request.clone();
    let res = props.response.clone();
    let ondeselect = {
        let ondeselect = props.ondeselect.clone();
        Callback::from(move |_| {
            ondeselect.emit(());
        })
    };
    html! {
        <div class={style}>
            <div>
                <button
                    class={(*tab==Tab::Request).then_some("tab_selected")}
                    onclick={
                        let ontabchange = ontabchange.clone();
                        move |_| ontabchange.emit(Tab::Request)
                    }
                    ~innerText="Request" />
                <button
                    class={(*tab==Tab::Response).then_some("tab_selected")}
                    onclick={
                        let ontabchange = ontabchange.clone();
                        move |_| ontabchange.emit(Tab::Response)
                    }
                    ~innerText="Response" />
                <button onclick={ondeselect} ~innerText="✖" />
            </div>
            {
                match *tab {
                    Tab::Request => html!{<Request request={req} />},
                    Tab::Response => html!{<Response response={res} />},
                }
            }
        </div>
    }
}
