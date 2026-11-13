// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! `authorized_keys` files per account: each key’s type, size, fingerprint, comment, options and line hash, never the key itself.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use systemlint_protocol::{Diagnostic, Input, Reply};

/// The fact naming each account’s files, which this op needs.
pub const NAMED: &str = "ssh.authorized-key-files";

/// `ssh.authorized-keys.<account>`: `files` with the stat of each file read, `keys` keyed `path:line`.
pub fn authorized(
    inputs: &[Input],
    facts: &BTreeMap<String, Value>,
) -> std::result::Result<Reply, String> {
    let named = facts
        .get(NAMED)
        .and_then(Value::as_object)
        .ok_or(format!("{NAMED} is not a map"))?;
    let mut reply = Reply::default();
    let mut read: BTreeMap<&str, (Value, Map<String, Value>)> = BTreeMap::new();
    for input in inputs {
        let Input::File(file) = input else { continue };
        let stat = file
            .stat
            .as_ref()
            .map_or(Value::Null, |s| serde_json::to_value(s).unwrap_or_default());
        let mut keys = Map::new();
        match &file.content {
            Some(text) => {
                for (number, line) in (1..).zip(text.lines()) {
                    match key(line) {
                        Ok(Some(k)) => drop(keys.insert(format!("{}:{number}", file.path), k)),
                        Ok(None) => {}
                        Err(message) => reply.diagnostics.push(Diagnostic {
                            path: file.path.clone(),
                            line: Some(number),
                            message,
                        }),
                    }
                }
            }
            None if file.content_base64.is_some() => reply.diagnostics.push(Diagnostic {
                path: file.path.clone(),
                line: None,
                message: "not UTF-8 text, so sshd reads no key from it".to_owned(),
            }),
            None => {}
        }
        read.insert(file.path.as_str(), (stat, keys));
    }
    for (account, paths) in named {
        let (mut files, mut keys) = (Map::new(), Map::new());
        for path in paths
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if let Some((stat, found)) = read.get(path) {
                files.insert(path.to_owned(), stat.clone());
                keys.extend(found.clone());
            }
        }
        if !files.is_empty() {
            reply
                .facts
                .insert(account.clone(), json!({"files": files, "keys": keys}));
        }
    }
    Ok(reply)
}

/// One `authorized_keys` line: `None` when blank or a comment, else the key or why sshd skips it.
pub fn key(raw: &str) -> std::result::Result<Option<Value>, String> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let (options, rest) = match line.split_whitespace().next().is_some_and(known) {
        true => (Map::new(), line),
        false => {
            let end = options_end(line)
                .ok_or("an option’s quotes never close, so sshd skips the line")?;
            (parse_options(&line[..end]), line[end..].trim_start())
        }
    };
    let mut words = rest.splitn(3, char::is_whitespace);
    let kind = words.next().unwrap_or_default();
    if !known(kind) {
        return Err(format!(
            "{kind} is not a key type sshd reads, so it skips the line"
        ));
    }
    let blob = words
        .next()
        .and_then(decode)
        .ok_or("the key is not base64, so sshd skips the line")?;
    let bits = bits(kind, &blob).ok_or(format!(
        "the key does not hold a {kind} key, so sshd skips the line"
    ))?;
    Ok(Some(json!({
        "type": kind,
        "bits": bits,
        "fingerprint": format!("SHA256:{}", encode(&Sha256::digest(&blob))),
        "comment": words.next().unwrap_or_default().trim(),
        "options": options,
        "line-sha256": Sha256::digest(raw.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>(),
    })))
}

// A key type sshd accepts, certificates included.
fn known(word: &str) -> bool {
    let base = word.strip_suffix("-cert-v01@openssh.com").unwrap_or(word);
    matches!(
        base,
        "ssh-rsa"
            | "ssh-dss"
            | "ssh-ed25519"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
            | "sk-ssh-ed25519@openssh.com"
    )
}

// The byte where the options end: the first blank outside double quotes.
fn options_end(line: &str) -> Option<usize> {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => return Some(i),
            _ => {}
        }
    }
    (!quoted).then_some(line.len())
}

/// The options field: each name lowercased, `true` for a flag, else every value it was given, quotes and `\"` undone.
pub fn parse_options(field: &str) -> Map<String, Value> {
    let mut options = Map::new();
    let (mut name, mut value, mut quoted, mut escaped, mut in_value) =
        (String::new(), String::new(), false, false, false);
    let mut flush = |name: &mut String, value: &mut String, in_value: bool| {
        let key = std::mem::take(name).to_ascii_lowercase();
        match in_value {
            true => {
                if let Value::Array(values) = options.entry(key).or_insert_with(|| json!([])) {
                    values.push(Value::from(std::mem::take(value)));
                }
            }
            false if !key.is_empty() => drop(options.insert(key, Value::Bool(true))),
            false => {}
        }
    };
    for c in field.chars() {
        match c {
            _ if escaped => {
                value.push(c);
                escaped = false;
            }
            '\\' if quoted => escaped = true,
            '"' if in_value => quoted = !quoted,
            ',' if !quoted => {
                flush(&mut name, &mut value, in_value);
                in_value = false;
            }
            '=' if !in_value => in_value = true,
            _ if in_value => value.push(c),
            _ => name.push(c),
        }
    }
    flush(&mut name, &mut value, in_value);
    options
}

/// The key size in bits from its wire blob, `None` when the blob is not of `kind`.
pub fn bits(kind: &str, blob: &[u8]) -> Option<u64> {
    let mut at = blob;
    let named = field(&mut at)?;
    if named != kind.as_bytes() {
        return None;
    }
    if kind.ends_with("-cert-v01@openssh.com") {
        field(&mut at)?;
    }
    let base = kind.strip_suffix("-cert-v01@openssh.com").unwrap_or(kind);
    match base {
        "ssh-rsa" => {
            field(&mut at)?;
            Some(magnitude(field(&mut at)?))
        }
        "ssh-dss" => Some(magnitude(field(&mut at)?)),
        "ecdsa-sha2-nistp384" => Some(384),
        "ecdsa-sha2-nistp521" => Some(521),
        _ => Some(256),
    }
}

// One length-prefixed field of the SSH wire format, advancing `at`.
fn field<'a>(at: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, rest) = at.split_first_chunk::<4>()?;
    let len = u32::from_be_bytes(*len) as usize;
    let (value, rest) = (rest.get(..len)?, rest.get(len..)?);
    *at = rest;
    Some(value)
}

// The bit length of an unsigned big-endian integer.
fn magnitude(mpint: &[u8]) -> u64 {
    let digits: &[u8] = match mpint.iter().position(|b| *b != 0) {
        Some(start) => &mpint[start..],
        None => &[],
    };
    digits.first().map_or(0, |first| {
        (digits.len() as u64 - 1) * 8 + u64::from(8 - first.leading_zeros())
    })
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 without padding, as `ssh-keygen -l` prints a fingerprint.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Standard base64, padding optional, `None` on any other byte.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut n, mut held) = (0u32, 0);
    for c in text.bytes() {
        n = n << 6 | ALPHABET.iter().position(|a| *a == c)? as u32;
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((n >> held) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public keys `ssh-keygen` made for these tests only, each beside the fingerprint `ssh-keygen -l` printed.
    const ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQVHjXf7wHmfkvbwaZCksrE3U8tnP/3vlEMvEzXpq9E alice@example";
    const ED25519_FINGERPRINT: &str = "SHA256:J0+AVcHzhOmegfSIHHR05iGf/zxJlOkthq0C5M2rdCs";
    const RSA1024: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC/oFCUFv7nvEvg79gmXGcxXUcCKHUQ12f4QoQ55JEelYWCvY33wvX/2p4s9azy7MnsvfjTeq+KWV/Iz9vklm3LeiNr9HUf/nrnFWZ/6ZmsMUjS+PVa9+/s1BqmF9MD9rQzH5ZPFoMMEviFBkIqjtuPzSu+9DSqaGLZNaRvRNwOfw== old";
    const RSA1024_FINGERPRINT: &str = "SHA256:k35ODz81KXzw/r4J3gBeEn0haj1GObKbZGcoaxLMRLM";

    #[test]
    fn base64_round_trips() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"\xff\x00\x10"] {
            assert_eq!(decode(&encode(bytes)).unwrap(), bytes);
        }
        assert_eq!(encode(b"foob"), "Zm9vYg");
        assert!(decode("a b").is_none());
    }

    #[test]
    fn a_plain_key_gives_type_bits_fingerprint_and_comment() {
        let k = key(ED25519).unwrap().unwrap();
        assert_eq!(k["type"], "ssh-ed25519");
        assert_eq!(k["bits"], 256);
        assert_eq!(k["comment"], "alice@example");
        assert_eq!(k["options"], json!({}));
        assert_eq!(k["fingerprint"], ED25519_FINGERPRINT);
        assert_eq!(
            k["line-sha256"].as_str().map(str::len),
            Some(64),
            "the raw line’s hash, which fix compares before commenting it out"
        );
        assert!(!k.to_string().contains("AAAAC3"), "the key never leaves");
        let rsa = key(RSA1024).unwrap().unwrap();
        assert_eq!(
            (&rsa["bits"], &rsa["fingerprint"]),
            (&json!(1024), &json!(RSA1024_FINGERPRINT))
        );
    }

    #[test]
    fn options_keep_quoted_commas_and_repeats() {
        let line = format!(
            r#"restrict,from="10.0.0.1,192.0.2.0/24",command="echo \"hi there\"",permitopen="a:1",PermitOpen="b:2" {ED25519}"#
        );
        let k = key(&line).unwrap().unwrap();
        assert_eq!(
            k["options"],
            json!({"restrict": true, "from": ["10.0.0.1,192.0.2.0/24"], "command": ["echo \"hi there\""], "permitopen": ["a:1", "b:2"]})
        );
        assert_eq!(k["type"], "ssh-ed25519");
    }

    #[test]
    fn blanks_and_comments_are_no_key_and_garbage_is_a_reason() {
        assert_eq!(key("  # x").unwrap(), None);
        assert_eq!(key("").unwrap(), None);
        assert!(key("ssh-ed25519 !!!").is_err());
        assert!(key(&ED25519.replacen("ssh-ed25519", "ssh-rsa", 1)).is_err());
        assert!(key(r#"from="x ssh-ed25519 AAAA"#).is_err());
        assert!(key("hello world").is_err());
    }

    #[test]
    fn rsa_and_dsa_sizes_come_from_the_modulus_and_prime() {
        let wire = |parts: &[&[u8]]| {
            parts.iter().fold(Vec::new(), |mut v, p| {
                v.extend((p.len() as u32).to_be_bytes());
                v.extend(*p);
                v
            })
        };
        let mut modulus = vec![0u8, 0x80];
        modulus.extend([0u8; 255]);
        assert_eq!(
            bits("ssh-rsa", &wire(&[b"ssh-rsa", &[1, 0, 1], &modulus])),
            Some(2048)
        );
        assert_eq!(
            bits("ssh-dss", &wire(&[b"ssh-dss", &[0, 0x7f, 0xff]])),
            Some(15)
        );
        assert_eq!(bits("ssh-dss", &wire(&[b"ssh-rsa", &[1]])), None);
        assert_eq!(bits("ssh-rsa", &wire(&[b"ssh-rsa", &[1]])), None);
        assert_eq!(
            bits(
                "ssh-rsa-cert-v01@openssh.com",
                &wire(&[
                    b"ssh-rsa-cert-v01@openssh.com",
                    b"nonce",
                    &[1, 0, 1],
                    &[0x01, 0]
                ])
            ),
            Some(9)
        );
        assert_eq!(
            bits("ecdsa-sha2-nistp521", &wire(&[b"ecdsa-sha2-nistp521"])),
            Some(521)
        );
    }
}
