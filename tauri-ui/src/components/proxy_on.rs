use stylist::yew::use_style;
use yew::prelude::*;

use crate::api::stop_proxy;
use crate::components::request::RequestTable;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub stop: Callback<()>,
}

#[function_component(ProxyOn)]
pub fn proxy_on(props: &Props) -> Html {
    let paused = use_state(|| false);
    let requests = use_mut_ref(Vec::new);
    let onclick = {
        let requests = requests.clone();
        let stop = props.stop.clone();
        Callback::from(move |_| {
            let requests = requests.clone();
            let stop = stop.clone();
            let on_stop = Callback::from(move |_: ()| {
                let mut r = requests.borrow_mut();
                r.drain(..);
                stop.emit(());
            });
            stop_proxy(Some(on_stop));
        })
    };
    let style = use_style!(
        r#"
        display: flex;
        flex-flow: column;
        align-items: center;
        vertical-align: baseline;
        overflow: auto;
        * {
        }
        "#
    );
    let pause_play_style = use_style!(
        r#"
        position:fixed;
        background:var(--bg-input);
        bottom: 10px;
        border:0;
        box-shadow: var(--box-shadow);
        border-radius: 10px;
        padding: 3px  10px;
        button {
            font-size: 1rem;
            height:30px;
            width: 30px;
            border:0;
            background: var(--gradient);
            border-radius: 30px;
            color: rgba(255,255,255,0.8);
            margin: 5px;
        }
        button:nth-of-type(2){
            background: var(--bg-color-secondary);
            color: var(--font-color);
        }
        "#
    );
    let is_paused = *paused;
    html! {
        <div class={style}>
            <div class={pause_play_style}>
                <button
                    onclick={Callback::from(move |_| paused.set(!is_paused))}
                    ~innerText={ if *paused {"▶"} else {"⏸"} }/>
                <button {onclick} ~innerText={"⏹"} />
            </div>
            <RequestTable paused={is_paused} {requests} />
        </div>
    }
}
