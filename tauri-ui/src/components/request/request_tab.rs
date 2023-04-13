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
            <div class="single_header">
                <strong ~innerText="Method:" />
                <p ~innerText={format!("{:?}", req.method())} />
            </div>
            <div class="single_header">
                <strong ~innerText="Version:" />
                <p ~innerText={format!("{:?}", req.version())} />
            </div>
            <div class="single_header">
                <strong ~innerText="Timestamp: " />
                <p ~innerText={format!("{:?}", req.time())} />
            </div>
        </TabView>
    }
}
