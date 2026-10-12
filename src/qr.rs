//! Renders the pairing URI and a terminal QR code.

use iroh::Endpoint;

use crate::auth::{scope_json, TokenInfo};

/// Print the binding block to stdout. The token is a secret until it expires:
/// it goes to stdout for the operator to copy/scan, never to tracing.
pub fn print_binding(endpoint: &Endpoint, token: &TokenInfo) {
    let node = endpoint.id();
    let uri = token.uri(node);
    println!("================ raemote binding ================");
    println!("  node id : {node}");
    println!("  token   : {} ({} chars)", token.token_hex, token.token_hex.len());
    println!(
        "  expires : unix {} (in {}s)",
        token.expires_at_unix,
        token.ttl.as_secs()
    );
    println!("  access  : {}", scope_json(&token.scope));
    println!("  uri     : {uri}");
    println!("=================================================");

    match qrcode::QrCode::new(uri.as_bytes()) {
        Ok(code) => {
            let qr = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .quiet_zone(true)
                .build();
            println!("\n{qr}");
        }
        Err(e) => println!("\n(could not render QR code: {e})"),
    }
}
