use wasm_bindgen::prelude::JsCast;
use web_sys::{HtmlInputElement, HtmlOptionElement, HtmlSelectElement};
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct TextInputProps {
    pub value: String,
    pub onchange: Callback<String>,
}

#[function_component(TextInput)]
pub fn text_input(props: &TextInputProps) -> Html {
    let TextInputProps { value, onchange } = props.clone();
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

#[derive(Clone, PartialEq, Properties)]
pub struct MultipleSelectInputProps {
    pub options: Vec<String>,
    pub onchange: Callback<Vec<String>>,
    #[prop_or_default]
    pub selection: Option<Vec<String>>,
}

#[function_component(MultipleSelectInput)]
pub fn multiple_select_input(props: &MultipleSelectInputProps) -> Html {
    let MultipleSelectInputProps {
        options,
        selection,
        onchange,
    } = props.clone();
    let current_select = use_state(|| selection.unwrap_or(options.clone()));
    let onchange = {
        let current_select = current_select.clone();
        Callback::from(move |e: Event| {
            let e: HtmlSelectElement = e.target_dyn_into().unwrap();
            let options = e.selected_options();
            let selected_options = (0..options.length())
                .filter_map(|i| {
                    options
                        .item(i)
                        .map(|e| e.dyn_into::<HtmlOptionElement>().unwrap().value())
                })
                .collect::<Vec<String>>();
            current_select.set(selected_options.clone());
            onchange.emit(selected_options);
        })
    };
    html! {
        <select {onchange} class="method_filter" multiple={true}>
        {
            options.iter().map(|op| {
                let selected = current_select.contains(op);
            html!{
                <option {selected} value={op.clone()} ~innerText={op.clone()}/ >
            }}).collect::<Html>()
        }
        </select>
    }
}
