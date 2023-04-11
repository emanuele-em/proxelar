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
        justify-content: space-between;
        align-items:stretch;
        margin:25px auto;
        background: var(--bg-color);
        padding:5px;
        border-radius: 5px;
        border: 1px solid var(--bg-color); 

        button {
            margin: 0;
            min-width: fit-content;
            opacity: 0.6;
            padding: 8px 0;
            width: 100%;
            margin: 0 5px;
            font-size:.8rem;
            border-radius: 5px;
            font-weight: bold;
            border: 1px solid transparent;
            background: transparent;
        }
        .tab_selected {
            opacity: 1;
            background: white;
            border: 1px solid lightgrey;
        }
        "#
    );
    let style = use_style!(
        r#"
        position:fixed;
        margin: auto;
        top:0;
        bottom:0;
        left: 0;
        right: 0;
        width: 750px;
        height: 450px;
        background: #fff;
        z-index: 999999;
        padding:20px;
        border-radius: 15px;

        .delete_button{
            color: var(--bg-color);
            border: 1px solid var(--bg-color);
            position:absolute;
            right: 10px;
            top: 10px;
            height: 25px;
            width: 25px;
            text-align:center;
            background: white;
            border-radius: 5px;
            padding:0;
            font-size: 18px;
        }

        "#
    );
    let background = use_style!(
        r#"
            position:fixed;
            top:0;
            bottom:0;
            left:0;
            right:0;
            width:100vw;
            height: 100vh;
            background:rgba(0,0,0,.6);
            content: "";
            z-index: 99999;

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
        <div>
            <div class={background}/>
            <div class={style}>
                <button class="delete_button" onclick={ondeselect} ~innerText="×" />
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
                </div>
                {
                    match *tab {
                        Tab::Request => html!{<RequestTab request={req} />},
                        Tab::Response => html!{<ResponseTab response={res} />},
                    }
                }
            </div>
        </div>
    }
}
