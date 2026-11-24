//! The TOTP enrollment QR code, rendered to SVG in Rust and shown as an
//! image (a `data:` URL), so nothing outside the console draws it and the
//! secret never leaves the page.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

use super::Invalid;

/// Smallest rendered side, in pixels: comfortably scannable from a screen.
const MIN_SIDE_PX: u32 = 220;

/// `text` (an `otpauth://` URI) as an SVG QR code.
pub fn svg(text: &str) -> Result<String, Invalid> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|e| Invalid::new(format!("The QR code couldn't be drawn ({e}).")))?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(MIN_SIDE_PX, MIN_SIDE_PX)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build())
}

/// `text` as a QR code in a `data:image/svg+xml` URL for an `<img>`.
pub fn data_url(text: &str) -> Result<String, Invalid> {
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(svg(text)?)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/localhost%3A8090:dev-owner?secret=JBSWY3DPEHPK3PXP&issuer=localhost%3A8090&algorithm=SHA1&digits=6&period=30";

    #[test]
    fn renders_an_svg_of_at_least_the_minimum_size() {
        let s = svg(URI).unwrap();
        assert!(s.contains("<svg"), "{s}");
        assert!(s.contains("#000000") && s.contains("#ffffff"));
        let width: u32 = s
            .split("width=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .and_then(|w| w.parse().ok())
            .unwrap();
        assert!(width >= MIN_SIDE_PX, "{width}");
    }

    #[test]
    fn the_data_url_decodes_to_the_svg() {
        let url = data_url(URI).unwrap();
        let b64 = url.strip_prefix("data:image/svg+xml;base64,").unwrap();
        let decoded = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();
        assert_eq!(decoded, svg(URI).unwrap());
    }

    #[test]
    fn oversized_input_is_an_error_not_a_panic() {
        assert!(svg(&"x".repeat(10_000)).is_err());
    }
}
