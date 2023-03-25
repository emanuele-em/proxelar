use super::header::Header;
use proxyapi_models::ProxiedRequest;
use stylist::yew::use_style;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub request: ProxiedRequest,
}

#[function_component(RequestTab)]
pub fn request_tab(props: &Props) -> Html {
    let req = props.request.clone();
    let body = req.body().clone();
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
                <strong ~innerText="Method:" />
                <span ~innerText={format!("{:?}", req.method())} />
            </p>
            <p>
                <strong ~innerText="Version:" />
                <span ~innerText={format!("{:?}", req.version())} />
            </p>
            <p>
                <strong ~innerText="Time Stamp:" />
                <span ~innerText={format!("{:?}", req.time())} />
            </p>
            <details>
                <summary><strong ~innerText="Headers" /></summary>
                <hr/>
                <Header headers={req.headers().clone()} />
            </details>
            <details>
                <summary><strong ~innerText="body" /></summary>
                <hr/>
                if let Ok(body) = std::str::from_utf8(&body) {
                    <p ~innerText={body.to_string()} />
                } else {
                    <p ~innerText={format!("{:?}", body)} />
                }
            </details>
        </div>
    }
}
