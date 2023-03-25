use http::HeaderMap;
use stylist::yew::use_style;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub children: Children,
}

#[function_component(TabView)]
pub fn tab_view(props: &Props) -> Html {
    let properties = props.children.clone();
    let body = props.body.clone();
    let headers = props.headers.clone();
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
            <details>
                <summary><strong ~innerText="Properties" /></summary>
                <hr/>
                {properties}
            </details>
            <details>
                <summary><strong ~innerText="Headers" /></summary>
                <hr/>
                {
                    headers.iter().map(
                        |(key, value)| {
                            html!{
                                <p>
                                    <strong ~innerText={format!("{}:",key)} />
                                    <span ~innerText={value.to_str().unwrap_or("").to_string()} />
                                </p>
                            }
                        }
                    ).collect::<Html>()
                }
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
