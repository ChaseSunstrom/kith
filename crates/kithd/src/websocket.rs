//! The WebSocket (RFC 6455) that kubectl exec, attach and cp speak to kithd, written here with no
//! new dependency: the accept key, and the frames (frame.rs, which the `kith` command shares).

use base64::Engine;

mod frame;
pub(crate) use frame::*;

/// The GUID RFC 6455 section 1.3 appends to the client's key before the SHA-1.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The Sec-WebSocket-Accept answer to a client's Sec-WebSocket-Key, or None when the key is not
/// 16 bytes in base64.
pub(crate) fn accept_key(client_key: &str) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD.decode(client_key).ok()?;
    if raw.len() != 16 {
        return None;
    }
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{client_key}{GUID}").as_bytes(),
    );
    Some(base64::engine::general_purpose::STANDARD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_accept_key_is_the_rfc_6455_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".to_string())
        );
    }

    #[test]
    fn websocket_accept_key_refuses_what_is_not_a_16_byte_key() {
        assert_eq!(accept_key("c2hvcnQ="), None, "\"short\" is 5 bytes");
        assert_eq!(accept_key("not base64!"), None);
        assert_eq!(accept_key(""), None);
    }
}
