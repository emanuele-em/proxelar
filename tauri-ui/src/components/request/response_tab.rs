use super::tab_view::TabView;
use proxyapi_models::ProxiedResponse;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub response: ProxiedResponse,
}

#[function_component(ResponseTab)]
pub fn response_tab(props: &Props) -> Html {
    let res = props.response.clone();
    let body = res.body().as_ref().to_vec();
    let headers = res.headers().clone();
    html! {
        <TabView {headers} {body}>
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
        </TabView>
    }
}
