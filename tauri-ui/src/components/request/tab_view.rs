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

        > div{
            margin-top:10px;
            margin-bottom:25px;
        }
        > div > strong{
            margin-top:20px;
            margin-bottom: 10px;
            display:block;
        }
        .headers {
        }
        .single_header{
            font-size:.7rem;
            display: flex;
            justify-content: flex-start;
            border-bottom: 1px solid var(--little-contrast);
            padding-top: 10px;
            padding-bottom:10px;

        }
        .single_header > strong {
            width:200px;
        }
        .single_header > p{
            margin:0;
            width: calc(100% - 200px);
            word-break: break-all;
        }
        .container_body{
            font-size:.7rem;
        }
        "#
    );
    html! {
        <div class={style}>
            <div>
                <strong ~innerText="Properties" />
                <div class="headers">
                    {properties}
                </div>
            </div>
            <div>
                <strong ~innerText="Headers" />
                <div class="headers">
                    {
                        headers.iter().map(
                            |(key, value)| {
                                html!{
                                    <div class="single_header">
                                        <strong ~innerText={format!("{}:",key)} />
                                        <p ~innerText={value.to_str().unwrap_or("").to_string()} />
                                    </div>
                                }
                            }
                        ).collect::<Html>()
                    } 
                </div>
                
            </div>
            if body.len() > 0 {
                <div>
                    <strong ~innerText="body" />
                    <div class="container_body">
                        if let Ok(body) = std::str::from_utf8(&body) {
                            <p ~innerText={ body.to_string()} />
                        } else {
                            <p ~innerText={format!("{:?}", body)} />
                        }
                    </div>
                </div>
            }
        </div>
    }
}
