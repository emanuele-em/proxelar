mod api;
mod components;

use components::app::App;

fn main() {
    yew::Renderer::<App>::new().render();
}
