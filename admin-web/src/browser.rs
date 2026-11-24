//! The few browser facilities the console uses beyond fetch: the clock and
//! the clipboard.

use wasm_bindgen_futures::JsFuture;

/// The current time, in unix seconds.
pub fn now_unix() -> i64 {
    // Date.now() is whole milliseconds since the epoch, well inside f64's
    // exact integer range; the division and floor give whole seconds.
    (js_sys::Date::now() / 1000.0).floor() as i64
}

/// Put `text` on the clipboard (the async Clipboard API, which needs the
/// page to be focused and served from a secure context).
pub async fn copy_text(text: &str) -> Result<(), String> {
    let window = web_sys::window().ok_or_else(|| "no browser window".to_owned())?;
    let promise = window.navigator().clipboard().write_text(text);
    JsFuture::from(promise)
        .await
        .map(|_| ())
        .map_err(|e| e.as_string().unwrap_or_else(|| format!("{e:?}")))
}
