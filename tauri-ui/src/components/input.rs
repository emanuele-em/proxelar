use web_sys::HtmlInputElement;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub value: String,
    pub onchange: Callback<String>,
}

#[function_component(TextInput)]
pub fn text_input(props: &Props) -> Html {
    let Props { value, onchange } = props.clone();
    let input_node_ref = use_node_ref();

    let oninput = {
        let input_node_ref = input_node_ref.clone();
        Callback::from(move |_| {
            let input = input_node_ref.cast::<HtmlInputElement>();
            if let Some(input) = input {
                onchange.emit(input.value());
            }
        })
    };

    html! {
        <input type="text" {value} {oninput} ref={input_node_ref} />
    }
}
