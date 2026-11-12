#!/usr/bin/env python3
"""Mutation check of the recovery plan's Phase 1, platform: the document signing keys' rotation — the sealed record of
published keys, revocation, adoption of the unsealed record, the re-seals (crates/cp-crypto/src/signing.rs) — and the
weak `ENCRYPTION_KEY` refused at start (crates/cp-crypto: cipher.rs, encryption.rs). The rotation's suite runs on a
database (Docker). See README.md.
"""
import sys

import _runner

S = "crates/cp-crypto/src/"
CI, EN, SI = S + "internal/cipher.rs", S + "encryption.rs", S + "signing.rs"
TE = ["-p", "vectispire-cp-crypto", "--test", "encryption"]
TR = ["-p", "vectispire-cp-crypto", "--test", "rotation"]

MUTANTS = [
    # ── the weak current key ──
    ("no placeholder refused", CI, "if PLACEHOLDERS.iter().any(|placeholder| letters.contains(placeholder)) {", "if false {", TE),
    ("the placeholder compared whole", CI, "if PLACEHOLDERS.iter().any(|placeholder| letters.contains(placeholder)) {", "if PLACEHOLDERS.iter().any(|placeholder| letters == *placeholder) {", TE),
    ("no NFKC before the comparison", CI, "    let letters: String = candidate\n        .nfkc()\n        .collect::<String>()", "    let letters: String = candidate\n        .chars()\n        .collect::<String>()", TE),
    ("marks kept as letters", CI, "        .filter(|c| {\n            matches!(", "        .filter(|c| {\n            c.is_alphanumeric() || matches!(", TE),
    ("a floor of nineteen", CI, "pub const MIN_PASSPHRASE_LENGTH: usize = 20;", "pub const MIN_PASSPHRASE_LENGTH: usize = 19;", TE),
    ("length in bytes", CI, "let length = candidate.chars().count();", "let length = candidate.len();", TE),
    ("the current key not checked", EN, "            refuse_a_weak_current_key(key)?;", "            let _ = key;", TE),
    # ── the record of published keys ──
    ("a recorded id trusted", SI, "if cosign::key_id(&key) != *claimed {", "if false {", TR),
    ("a revoked key's match valid", SI, "        KeyStatus::Revoked => (\n            false,", "        KeyStatus::Revoked => (\n            true,", TR),
    ("no revocation status", SI, "        if self.revoked.contains(&key.key_id) {\n            KeyStatus::Revoked", "        if false {\n            KeyStatus::Revoked", TR),
    ("only the active key verifies", SI, "                if cosign::verify(payload, signature, &key.verifying) {\n                    return Ok(answer(key.key_id, key.status, key.retired_at));\n                }", "                if key.status == KeyStatus::Active && cosign::verify(payload, signature, &key.verifying) {\n                    return Ok(answer(key.key_id, key.status, key.retired_at));\n                }", TR),
    ("the record read in the clear", SI, "        let read = if Encryption::is_ciphertext(stored) {", "        let read = if !Encryption::is_ciphertext(stored) {\n            Some(self.read(Some(stored)))\n        } else if Encryption::is_ciphertext(stored) {", TR),
    ("the record opened under another context", SI, "let record = self.encryption.inspect(stored, KNOWN_KEYS_CONTEXT).await;\n            (record.state()", "let record = self.encryption.inspect(stored, CONTEXT).await;\n            (record.state()", TR),
    ("the active key never retired", SI, "                    Known { retired_at: Some(now), ..k.clone() }", "                    k.clone()", TR),
    ("the rolling restart takes the record back", SI, "                    && retired_at > self.started_at", "                    && false", TR),
    ("the replaced stored key forgotten", SI, "        if self.configured\n            && let Some(stored) = self.stored_public_key().await?", "        if false\n            && let Some(stored) = self.stored_public_key().await?", TR),
    ("no registration before signing", SI, "                self.register(key).await?;", "", TR),
    ("the unsealed record adopted whole", SI, ".filter(|k| self.adopted.contains(&k.key_id) && !present.contains(k.key_id.as_str()))", ".filter(|k| !present.contains(k.key_id.as_str()))", TR),
    ("no adoption", SI, ".filter(|k| self.adopted.contains(&k.key_id) && !present.contains(k.key_id.as_str()))", ".filter(|_| false)", TR),
    ("the record never re-sealed", SI, "        if record.state() != SecretState::PreviousKey {\n            return Ok(());", "        if true {\n            return Ok(());", TR),
    ("the private key never re-sealed", SI, "        if secret.state() == SecretState::PreviousKey {\n            let resealed", "        if false {\n            let resealed", TR),
    ("a revoked generated key starts", SI, "        if !keys.configured && !keys.revoked.is_empty() {", "        if false {", TR),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS))
