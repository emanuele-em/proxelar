use proxyapi_models::RequestInfo;
use stylist::yew::use_style;
use url::Url;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct RowProps {
    pub exchange: RequestInfo,
    pub idx: usize,
    pub ondelete: Callback<usize>,
    pub onselect: Callback<usize>,
}

#[function_component(RequestRow)]
pub fn request_row(props: &RowProps) -> Html {
    let delete_style = use_style!(
        r#"
        margin: auto;
        display: block;
        padding:10px;
        text-shadow: var(--box-shadow);
        border:none;
        background:transparent;
        "#
    
    );
    let path_style = use_style!(
       r#"
       position:relative;
       
       .hide{
        max-height: 0;
        transition: all .2s ease-in-out;
        overflow:hidden;
        margin:0;
       }
       :hover .hide{
        max-height:500px;
        transition: all .2s ease-in-out;
       }
       .b{
        display:block;
        float:left;
       }
       .headers{
        height:100%;
        width: 100%;
        display: flex;
        justify-content:flex-start;
        align-items:center;
        pointer-events:none;
        padding-left: 10px;
        margin:3px 0;
        font-size: .7rem;
       }
       .headers:first-child
       {
        margin-top:10px;
       }
       span{
        max-width: calc(100% - 100px);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        display:block;
       } 
       "#
    );
    match props.exchange {
        RequestInfo(Some(ref req), Some(ref res)) => {
            let idx = props.idx;
            let method = req.method().to_string();
            let authority = req.uri().authority().unwrap().to_string();
            let query = Url::parse(&req.uri().to_string()).unwrap(); 
            let query = query.query_pairs()
            .map(|(key, value)| (key.to_string(), value.to_string()));
            let ondelete = props.ondelete.clone();
            let onselect = props.onselect.clone();
            html! {
                <tr onclick={move |_| {onselect.emit(idx)}}>
                    <td class={path_style}>
                        <b>{authority}</b><br />
                        <div class="hide">
                            {
                                for query.map(|(key, value)| {
                                    html! {
                                        <div class="headers"><b>{ format!("{}",key) }</b><span>{ format!(" = {}",value) }</span></div>
                                    }
                                })
                            }
                        </div>
                    </td>
                    <td class={classes!("method", &method)} >{method}</td>
                    <td>{res.status().to_string()}</td>
                    <td>{req.body().len()}</td>
                    <td>{((res.time() - req.time()) as f64 * 1e-6).trunc()}</td>
                    <td>
                        <button title={"Delete"} class={delete_style}
                            onclick={move |e: MouseEvent| {ondelete.emit(idx); e.stop_immediate_propagation();}}
                            ~innerText="🗑"/>
                    </td>
                </tr>
            }
        }
        _ => {
            html! {
                <tr>{"Parsing Failed"}</tr>
            }
        }
    }

}
