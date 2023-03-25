use super::tab_view::TabView;
use proxyapi_models::ProxiedRequest;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub request: ProxiedRequest,
}

#[function_component(RequestTab)]
pub fn request_tab(props: &Props) -> Html {
    let req = props.request.clone();
    let body = req.body().as_ref().to_vec();
    let headers = req.headers().clone();
    html! {
        <TabView {headers} {body}>
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
        </TabView>
    }
}
