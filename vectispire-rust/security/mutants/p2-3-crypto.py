#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.3: encryption at rest, the key's derivation, Vault Transit, the signing key
(crates/cp-crypto) and the sealing side of the shared crate (crates/crypto: seal). The engine suite (Docker) runs only
for the mutants of the signing key's storage, which nothing else can see. See README.md.
"""
import sys

import _runner

S = "crates/cp-crypto/src/"
CI, VA, CO, EN, SI = S + "internal/cipher.rs", S + "internal/vault.rs", S + "internal/cosign.rs", S + "encryption.rs", S + "signing.rs"
SE = "crates/crypto/src/lib.rs"
T = ["-p", "vectispire-cp-crypto", "--lib", "--test", "reference_set", "--test", "encryption", "--test", "signing"]
TE = ["-p", "vectispire-cp-crypto", "--test", "engines"]
TS = ["-p", "vectispire-crypto"]

MUTANTS = [
    # ── the cipher and the key ──
    ("another prefix", CI, 'pub const FORMAT_PREFIX: &str = "v2:";', 'pub const FORMAT_PREFIX: &str = "v3:";', T),
    ("a 16-byte nonce", CI, "const NONCE_LENGTH: usize = 12;", "const NONCE_LENGTH: usize = 16;", T),
    ("no length floor", CI, "if combined.len() < NONCE_LENGTH + TAG_LENGTH {", "if false {", T),
    ("scrypt at 2^14", CI, "const SCRYPT_LOG_N: u8 = 15;", "const SCRYPT_LOG_N: u8 = 14;", T),
    ("another salt", CI, 'const SCRYPT_SALT: &[u8] = b"vectispire.encryption.v2";', 'const SCRYPT_SALT: &[u8] = b"vectispire.encryption.v3";', T),
    ("no NFKC", CI, "secret.nfkc().collect::<String>()", "secret.to_owned()", T),
    ("the passphrase trimmed", CI, "secret.nfkc().collect::<String>()", "java::trim(secret).nfkc().collect::<String>()", T),
    ("the key's shape untrimmed", CI, "let trimmed = java::trim(secret);", "let trimmed = secret;", T),
    ("no 43-character key", CI, "&& (43..=44).contains(&body.len())", "&& (44..=44).contains(&body.len())", T),
    ("no URL alphabet in the shape", CI, "matches!(b, b'+' | b'/' | b'_' | b'-')", "matches!(b, b'+' | b'/')", T),
    ("the basic decoder for a URL key", CI, "let decoder = if trimmed.contains(['-', '_']) { URL } else { BASIC };", "let decoder = BASIC;", T),
    ("the unused bits checked", CI, ".with_decode_allow_trailing_bits(true),", ".with_decode_allow_trailing_bits(false),", T),
    ("the padding required", CI, ".with_decode_padding_mode(DecodePaddingMode::Indifferent)", ".with_decode_padding_mode(DecodePaddingMode::RequireCanonical)", T),
    ("bytes that are not UTF-8 refused", CI, "Some(Secret::new(String::from_utf8_lossy(&plain).into_owned()))", "Some(Secret::new(String::from_utf8(plain.to_vec()).ok()?))", T),
    ("the second key current", CI, "if index == 0 { SecretState::Current }", "if index <= 1 { SecretState::Current }", T),
    ("no associated data on reading", CI, "Payload { msg: body, aad: context.as_bytes() }", 'Payload { msg: body, aad: b"" }', T),
    ("every key equal", CI, "bool::from(self.0.ct_eq(&*other.0))", "true", T),
    # ── the service ──
    ("a blank key is a key", EN, ".filter(|key| !java::is_blank(key.expose()))", ".filter(|_| true)", T),
    ("previous keys untrimmed", EN, ".map(|key| java::trim(key.expose())).filter(|key| !key.is_empty())", ".map(|key| key.expose()).filter(|key| !key.is_empty())", T),
    ("the KMS type keeps its case", EN, 'let kms_type = java::to_lower_root(setting(&config.kms_type).unwrap_or("local"));', 'let kms_type = setting(&config.kms_type).unwrap_or("local").to_owned();', T),
    ("settings untrimmed", EN, "value.as_deref().map(java::trim).filter(|value| !value.is_empty())", "value.as_deref().filter(|value| !value.is_empty())", T),
    ("the refusals swapped", EN, 'if endpoint.is_none() { "no endpoint was provided" }', 'if endpoint.is_some() { "no endpoint was provided" }', T),
    ("Vault without a token falls back", EN, "(true, endpoint, _) => {", "(true, endpoint, _) if false => {", T),
    ("an empty value needs a key", EN, "        if plain.is_empty() {\n            return Ok(String::new());\n        }\n        if !self.is_configured() {", "        if !self.is_configured() {", T),
    ("Vault's blank token is not a missing key", EN, "        if !self.is_configured() {\n            return Err(EncryptionError::MissingKey);\n        }\n        match &self.kms {", "        match &self.kms {", T),
    ("a Vault ciphertext is clear", EN, "stored.starts_with(FORMAT_PREFIX) || stored.starts_with(CIPHERTEXT_PREFIX)", "stored.starts_with(FORMAT_PREFIX)", T),
    ("readSecret trims the Rust way", EN, "let value = java::trim(stored);", "let value = stored.trim();", T),
    # ── Vault ──
    ("the endpoint's slashes kept", VA, "endpoint: endpoint.trim_end_matches('/').to_owned(),", "endpoint: endpoint.to_owned(),", T),
    ("another default key", VA, 'key_name: named(key_name, "vectispire"),', 'key_name: named(key_name, "vectispire-key"),', T),
    ("the derivation not checked", VA, "if !context.is_empty() && !self.key_is_derived().await? {", "if false && !self.key_is_derived().await? {", T),
    ("an unknown derivation is derived", VA, "self.derived_if_known().await.ok_or_else(|| {", "Some(self.derived_if_known().await.unwrap_or(true)).ok_or_else(|| {", T),
    ("the answer not kept", VA, "                *self.derived.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(derived);\n", "", T),
    ("a string is a boolean", VA, '.and_then(Value::as_bool))', '.and_then(|v| v.as_bool().or(v.as_str().map(|s| s == "true"))))', T),
    ("an empty context sent", VA, "        if !context.is_empty() {\n            body.insert(\"context\".to_owned(), Value::String(BASIC.encode(context.as_bytes())));\n        }\n        let body = Value::Object(body).to_string();\n        let response = self\n            .door\n            .sender\n            .send(\n                Method::Post,\n                destination,",
     "        body.insert(\"context\".to_owned(), Value::String(BASIC.encode(context.as_bytes())));\n        let body = Value::Object(body).to_string();\n        let response = self\n            .door\n            .sender\n            .send(\n                Method::Post,\n                destination,", T),
    ("any status encrypts", VA, "        if response.status != 200 {\n            tracing::error!", "        if false {\n            tracing::error!", T),
    ("a null is no ciphertext", VA, 'match ciphertext.and_then(|node| java::as_text(Some(node), Some("null"))) {', "match ciphertext.and_then(|node| node.as_str().map(str::to_owned)) {", T),
    ("a blank ciphertext stored", VA, "Some(text) if !java::is_blank(&text) => Ok(text),", "Some(text) => Ok(text),", T),
    ("a blank plaintext read", VA, "            if let Some(text) = plaintext.and_then(|node| java::as_text(Some(node), Some(\"null\")))\n                && !java::is_blank(&text)\n",
     "            if let Some(text) = plaintext.and_then(|node| java::as_text(Some(node), Some(\"null\")))\n", T),
    ("Vault's answer is a previous key", VA, "Some(plain) => Decrypted::new(plain, SecretState::Current),", "Some(plain) => Decrypted::new(plain, SecretState::PreviousKey),", T),
    ("another token header", VA, '&[("X-Vault-Token", self.token.expose()), ("Content-Type", "application/json")],\n                Some(&body),\n                TIMEOUT,\n                "Vault KMS encrypt",',
     '&[("X-Vault-Tok", self.token.expose()), ("Content-Type", "application/json")],\n                Some(&body),\n                TIMEOUT,\n                "Vault KMS encrypt",', T),
    ("the guard's refusal wrapped", VA, "let destination = self.destination(\"encrypt\")?;", "let destination = self.destination(\"encrypt\").map_err(|e| EncryptionError::Kms(e.to_string()))?;", T),
    # ── P-256 and the signing key ──
    ("P-384 unreadable", CO, "    if OTHER_JDK_CURVES.contains(&curve) {\n        return Err(KeyRefusal::NotP256);\n    }\n", "", T),
    ("any SEC1 curve", CO, "Some(curve) if curve == P256 => {", "Some(_) => {", T),
    ("a SEC1 key without a curve", CO, "        _ => Err(KeyRefusal::Unreadable),\n    }\n}", "        None => p256::SecretKey::from_sec1_der(der).map(SigningKey::from).map_err(|_| KeyRefusal::Unreadable),\n        _ => Err(KeyRefusal::Unreadable),\n    }\n}", T),
    ("markers kept", CO, "            Some((marker, tail)) if !marker.is_empty() && tail.starts_with(\"----\") => {", "            Some((marker, tail)) if false && !marker.is_empty() && tail.starts_with(\"----\") => {", T),
    ("upper-case key id", CO, '.map(|byte| format!("{byte:02x}"))', '.map(|byte| format!("{byte:02X}"))', T),
    ("CRLF public PEM", CO, "key.to_public_key_pem(LineEnding::LF)", "key.to_public_key_pem(LineEnding::CRLF)", T),
    ("a signature not trimmed", CO, "BASIC.decode(vectispire_domain::java::trim(signature))", "BASIC.decode(signature)", T),
    ("DSSE lengths swapped", CO, 'payload_type.len(), payload.len()', 'payload.len(), payload_type.len()', T),
    ("another row context", SI, 'const CONTEXT: &str = "internal:document_signing_key";', 'const CONTEXT: &str = "internal:signing_key";', T),
    ("another row", SI, 'pub const STORED_KEY: &str = "internal.document_signing_key";', 'pub const STORED_KEY: &str = "internal.signing_key";', T),
    ("the configured key untrimmed", SI, "let configured = java::trim(configured);", "let configured = configured;", T),
    ("an unreadable row parsed", SI, "        if secret.state() == SecretState::Unreadable {\n            return Err(SigningError::Unreadable);", "        if false {\n            return Err(SigningError::Unreadable);", T),
    ("no key is a Vault failure", SI, "EncryptionError::MissingKey => SigningError::MissingKey,", "EncryptionError::MissingKey => SigningError::Encryption(EncryptionError::MissingKey),", T),
    ("a supplied key is never ours", SI, "let is_ours = key_id == ours.key_id;", "let is_ours = false;", T),
    ("the generated key, not the stored one", SI, "let key = self.decrypt(java::trim(&kept)).await?;", "let _ = kept; let key = KeyMaterial::of(generated.clone());", TE),
    ("the row overwritten", SI, "let inserted = self.store.store_internal_if_absent(STORED_KEY, &encrypted).await?;", "let inserted = true;", TE),
    # ── seal, in the shared crate ──
    ("the nonce drawn first", SE, "    let mut ephemeral_secret = [0u8; 32];\n    random.fill_bytes(&mut ephemeral_secret);\n",
     "    let mut ephemeral_secret = [0u8; 32];\n    let mut early = [0u8; NONCE_LENGTH];\n    random.fill_bytes(&mut early);\n    random.fill_bytes(&mut ephemeral_secret);\n", TS),
    ("the context not bound", SE, "    associated.extend_from_slice(context.value().as_bytes());\n    let sealed = cipher", "    let sealed = cipher", TS),
    ("the salt's keys swapped", SE, "session_key(shared.as_bytes(), &ephemeral.public_spki, &recipient_spki)", "session_key(shared.as_bytes(), &recipient_spki, &ephemeral.public_spki)", TS),
    ("the recipient's unused bits checked", SE, "        .with_decode_allow_trailing_bits(true),\n);\n\n/// Seals", "        .with_decode_allow_trailing_bits(false),\n);\n\n/// Seals", TS),
    ("the recipient trimmed", SE, "JAVA_DECODER.decode(recipient_public)", "JAVA_DECODER.decode(recipient_public.trim())", TS),
    ("any 44 bytes a key", SE, ".strip_prefix(X25519_SPKI_PREFIX.as_slice())", ".get(X25519_SPKI_PREFIX.len()..)", TS),
]

# Removed as indistinguishable from the original, each for its reason, not counted as killed:
# - "an unreadable secret read as its plain text" (read_secret without its UNREADABLE branch): an unreadable
#   Decrypted carries "", so the branch changes the log line and not the answer.
# - "a blank value sent to Vault" (VaultKms::inspect's blank check as `is_empty`): a blank value does not start
#   with `vault:`, and the local keys answer UNREADABLE for it either way.
# - "LocalKms encrypts nothing" (its own empty check): Encryption::encrypt answers an empty value before the KMS.
# - "three padding characters" (the key's shape allowing `===`): no base64 of 43 or 44 characters ends in three
#   `=`, so the decoder refuses what the shape let through and the secret is a passphrase either way.
# - "encrypting without a current key" (LocalKms::encrypt without its `current` filter): Encryption::encrypt refuses
#   with MissingKey before the local KMS is asked; the filter is the defence Java's LocalKmsProvider also keeps.
# - "a key configured twice tried twice" (no de-duplication): a duplicate always sits after its first occurrence, so
#   the first key to read a value — and the state it reports — is the same; Java drops it to try fewer keys.
# - "a blank key name is a name" (VaultKms's blank check as `is_empty`): Encryption trims the key name and drops a
#   blank one before VaultKms sees it, as EncryptionProperties' constructor does before VaultKmsProvider's.
# - the timeout (5 s) and the request labels: not observable by a stub that answers at once; the reference set
#   records Java's, and the code spells them once.



if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=600))
