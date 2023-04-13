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
            <div class="single_header">
                <strong ~innerText="Status:" />
                <p ~innerText={format!("{:?}", res.status())} />
            </div>
            <div class="single_header">
                <strong ~innerText="Version:" />
                <p ~innerText={format!("{:?}", res.version())} />
            </div>
            <div class="single_header">
                <strong ~innerText="Timestamp: " />
                <p ~innerText={format!("{:?}", res.time())} />
            </div>
        </TabView>
    }
}
