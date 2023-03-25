use http::HeaderMap;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub headers: HeaderMap,
}

#[function_component(Header)]
pub fn headers(props: &Props) -> Html {
    let headers = props.headers.clone();
    html! {
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
}
