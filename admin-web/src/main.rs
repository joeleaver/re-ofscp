//! re-ofscp admin UI entry point (rinch, browser-native DOM).
//!
//! Placeholder shell only — the user-management screens are built in the
//! implementation session. Talks to the server's admin API under `/api/admin`.

use rinch::prelude::*;
use rinch_core::element::ThemeProviderProps;
use wasm_bindgen::prelude::*;

#[component]
fn app() -> NodeHandle {
    rsx! {
        div { style: "padding: 32px; font-family: var(--rinch-font-family);",
            h1 { "re-ofscp" }
            p { "Admin console — user management is coming soon." }
            p { "OFSCP " {re_ofscp_types::OFSCP_VERSION} }
        }
    }
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    rinch_web::mount(ThemeProviderProps::default(), app);
}

fn main() {}
