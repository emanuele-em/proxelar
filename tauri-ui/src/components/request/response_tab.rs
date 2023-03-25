use super::header::Header;
use proxyapi_models::ProxiedResponse;
use stylist::yew::use_style;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub response: ProxiedResponse,
}

#[function_component(ResponseTab)]
pub fn response_tab(props: &Props) -> Html {
    let res = props.response.clone();
    let body = res.body().clone();
    let style = use_style!(
        r#"
        details {
            border: 1px solid;
            border-radius: 4px;
            padding: 0.5em 0;
        }
        "#
    );
    html! {
        <div class={style}>
            <p>
                <strong ~innerText="Status:" />
                <span ~innerText={format!("{:?}", res.status())} />
            </p>
            <p>
                <strong ~innerText="Version:" />
                <span ~innerText={format!("{:?}", res.version())} />
            </p>
            <p>
                <strong ~innerText="Time Stamp:" />
                <span ~innerText={format!("{:?}", res.time())} />
            </p>
            <details>
                <summary><strong ~innerText="Headers" /></summary>
                <hr/>
                <Header headers={res.headers().clone()} />
                <hr/>
            </details>
            <details>
                <summary><strong ~innerText="body" /></summary>
                <hr/>
                if let Ok(body) = std::str::from_utf8(&body) {
                    <p ~innerText={body.to_string()} />
                } else {
                    <p ~innerText={format!("{:?}", body)} />
                }
                <hr/>
            </details>
        </div>
    }
}
