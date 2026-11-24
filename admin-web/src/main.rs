//! The re-ofscp admin console (rinch, browser-native DOM, served at
//! `/admin`). It talks only to the server's admin API under `/api/admin`
//! (docs/decisions/0005).
//!
//! * `logic`: everything that isn't UI, natively unit-tested.
//! * `api`, `browser`: the browser I/O (fetch, clock, clipboard).
//! * `session`: the signed-in admin, shared by every screen.
//! * `ui`: the screens.

mod api;
mod browser;
mod logic;
mod session;
mod ui;

use rinch_core::element::ThemeProviderProps;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    rinch_web::mount(ThemeProviderProps::default(), ui::app);
}

fn main() {}
