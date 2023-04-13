use crate::api::start_proxy;
use crate::components::input::TextInput;
use std::net::SocketAddr;
use stylist::yew::use_style;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub start: Callback<()>,
}

#[function_component(ProxyOff)]
pub fn proxy_off(props: &Props) -> Html {
    let proxy_addr = use_state(|| "127.0.0.1:8100".to_string());
    let error = use_state(|| None);
    let addr_changed = {
        let proxy_addr = proxy_addr.clone();
        let error_msg = error.clone();
        Callback::from(move |new_addr: String| {
            match new_addr.parse::<SocketAddr>() {
                Ok(_) => {
                    error_msg.set(None);
                }
                Err(error) => error_msg.set(Some(format!("{:?}", error.to_string()))),
            }
            proxy_addr.set(new_addr);
        })
    };

    let onclick = {
        let proxy_addr = proxy_addr.clone();
        let error_msg = error.clone();
        let start = props.start.clone();
        Callback::from(move |_| {
            let start = start.clone();
            match proxy_addr.parse::<SocketAddr>() {
                Ok(addr) => {
                    start_proxy(addr, Some(start));
                    error_msg.set(None);
                }
                Err(error) => error_msg.set(Some(format!("{:?}", error.to_string()))),
            }
        })
    };
    let style = use_style!(
        r#"
        display: flex;
        flex-flow: row;
        align-items: center;
        justify-content: center;
        position:relative;
        width:350px;
        margin:auto;
        input{
            height:40px;
            width:100%;
            line-height:40px;
            border-radius:50px;
            padding:10px; 
            border:none;
            padding-right:35px;
            padding-left:20px;
            
        }
        button {
          border-radius: 50%;
          height:30px;
          width: 30px;
          color:rgba(255,255,255,.8);
          border: none;
          background: var(--gradient);
          position:absolute;
          right:5px;
        }
        "#
    );
    html! {
            <div class={style}>
                    <TextInput value={proxy_addr.to_string()} onchange={addr_changed}/>
                    if let Some(ref error) = *error {
                        <p>{error}</p>
                    }
                    <button {onclick} ~innerText={"▶"}/>
            </div>
    }
}
