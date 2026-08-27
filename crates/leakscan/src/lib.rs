use base64::{Engine as _, engine::general_purpose::STANDARD};

/// A canary match found in a byte sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub canary_index: usize,
    pub encoding: String,
    pub byte_offset: usize,
}

/// Scans bytes for raw and encoded forms of each canary.
pub fn scan_bytes(haystack: &[u8], canaries: &[String]) -> Vec<Hit> {
    let mut hits = Vec::new();

    for (canary_index, canary) in canaries.iter().enumerate() {
        let variants = [
            ("raw", canary.as_bytes().to_vec(), false),
            (
                "base64",
                STANDARD.encode(canary.as_bytes()).into_bytes(),
                false,
            ),
            ("url", percent_encode(canary.as_bytes()), true),
            ("hex", hex_encode(canary.as_bytes()), true),
            (
                "json",
                serde_json::to_string(canary)
                    .expect("serializing a string cannot fail")
                    .into_bytes(),
                false,
            ),
        ];

        for (encoding, needle, ignore_ascii_case) in variants {
            for byte_offset in find_matches(haystack, &needle, ignore_ascii_case) {
                hits.push(Hit {
                    canary_index,
                    encoding: encoding.to_owned(),
                    byte_offset,
                });
            }
        }
    }

    hits
}

fn percent_encode(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = Vec::with_capacity(bytes.len() * 3);

    for &byte in bytes {
        encoded.push(b'%');
        encoded.push(HEX[(byte >> 4) as usize]);
        encoded.push(HEX[(byte & 0x0f) as usize]);
    }

    encoded
}

fn hex_encode(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Vec::with_capacity(bytes.len() * 2);

    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize]);
        encoded.push(HEX[(byte & 0x0f) as usize]);
    }

    encoded
}

fn find_matches(haystack: &[u8], needle: &[u8], ignore_ascii_case: bool) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }

    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(byte_offset, window)| {
            let matches = if ignore_ascii_case {
                window
                    .iter()
                    .zip(needle)
                    .all(|(haystack_byte, needle_byte)| {
                        haystack_byte.eq_ignore_ascii_case(needle_byte)
                    })
            } else {
                window == needle
            };

            matches.then_some(byte_offset)
        })
        .collect()
}
