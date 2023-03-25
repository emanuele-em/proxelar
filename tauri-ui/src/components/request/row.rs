use proxyapi_models::RequestInfo;
use stylist::yew::use_style;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct RowProps {
    pub exchange: RequestInfo,
    pub idx: usize,
    pub ondelete: Callback<usize>,
    pub onselect: Callback<usize>,
}

#[function_component(RequestRow)]
pub fn request_row(props: &RowProps) -> Html {
    let delete_style = use_style!(
        r#"
        margin: auto;
        display: block;
        font-size: 2rem;
        "#
    );
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
                        <button class={delete_style} style=""
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
