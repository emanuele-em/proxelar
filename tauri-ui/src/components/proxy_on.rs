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
            margin: 0.5em;
        }
        div:first-child button {
            font-size: 2em;
            width: 5em;
        }
        "#
    );
    let is_paused = *paused;
    html! {
        <div class={style}>
            <div>
                <button
                    onclick={Callback::from(move |_| paused.set(!is_paused))}
                    ~innerText={ if *paused {"▶"} else {"⏸"} }/>
                <button {onclick} ~innerText={"⏹"} />
            </div>
            <RequestTable paused={is_paused} {requests} />
        </div>
    }
}
