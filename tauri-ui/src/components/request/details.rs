use super::request_tab::RequestTab;
use super::response_tab::ResponseTab;
use proxyapi_models::{ProxiedRequest, ProxiedResponse};
use stylist::yew::use_style;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub request: ProxiedRequest,
    pub response: ProxiedResponse,
    pub ondeselect: Callback<()>,
}

#[derive(Default, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Request,
    Response,
}

#[function_component(RequestDetails)]
pub fn request_details(props: &Props) -> Html {
    let tab_style = use_style!(
        r#"
        display: flex;
        button {
            font-size: 2em;
            margin: 0;
            min-width: fit-content;
            padding: 0 .5rem;
            opacity: 0.6;
        }
        .tab_selected {
            opacity: 1;
        }
        button:last-child {
            opacity: 1;
            width: 2rem;
            margin-left: auto;
            align-self: flex-end;
        }
        "#
    );
    let style = use_style!(
        r#"
        display: flex;
        flex-flow: column;
        flex: 1;
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
            <div class={tab_style}>
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
                    Tab::Request => html!{<RequestTab request={req} />},
                    Tab::Response => html!{<ResponseTab response={res} />},
                }
            }
        </div>
    }
}
