use proxyapi_models::{ProxiedRequest, ProxiedResponse};
use stylist::yew::use_style;
use yew::prelude::*;
#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub request: ProxiedRequest,
    pub response: ProxiedResponse,
    pub ondeselect: Callback<()>,
}

#[function_component(RequestDetails)]
pub fn request_details(props: &Props) -> Html {
    let style = use_style!(
        r#"
        display: flex;
        flex-flow: column;
        flex: 1;
        "#
    );
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
            <button onclick={ondeselect} ~innerText="✖" />
            {format!("{:?}{:?}", req, res)}
        </div>
    }
}
