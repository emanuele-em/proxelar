use proxyapi_models::RequestInfo;
use yew::prelude::*;
#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub exchange: RequestInfo,
    pub ondelete: Callback<()>,
}

#[function_component(RequestHeader)]
pub fn request_header() -> Html {
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
pub fn request_row(props: &Props) -> Html {
    match props.exchange {
        RequestInfo(Some(ref req), Some(ref res)) => {
            let method = req.method().to_string();
            let ondelete = props.ondelete.clone();
            html! {
                <tr>
                    <td>{req.uri().to_string()}</td>
                    <td class={classes!("method", &method)} >{method}</td>
                    <td>{res.status().to_string()}</td>
                    <td>{req.body().len()}</td>
                    <td>{((res.time() - req.time()) as f64 * 1e-6).trunc()}</td>
                    <td><button onclick={move |_| {ondelete.emit(())}} ~innerText="🗑 "/></td>
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
