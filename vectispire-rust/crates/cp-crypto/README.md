# vectispire-cp-crypto

The control plane's crypto module in Rust — `core.crypto` (`EncryptionService`, `VaultKmsProvider`,
`SigningKeyService`) and the parts of `common.domain.crypto` it is built on (`SecretCipher`, `EncryptionKey`,
`LocalKmsProvider`, the P-256 half of `CosignSigner`) — plan, Phase 2 task 2.3. In progress, not shipped: the Java
control plane is the product.

A shared foundation module (`edges.toml`: `crypto → outbound, settings`): every module may use it.

## What it holds

| | Java | Here |
|---|---|---|
| Encryption at rest | `EncryptionService` | `Encryption::{new, encrypt, inspect, read_secret, is_ciphertext, is_configured, is_externally_managed}` |
| The key's derivation | `EncryptionKey.derive` | `internal::cipher::EncryptionKey` — 32 bytes of base64 as they are, otherwise NFKC then scrypt (N = 2^15, r = 8, p = 1, salt `vectispire.encryption.v2`) |
| The format | `SecretCipher` | `v2:` + base64(nonce 12 ‖ ciphertext ‖ tag 16), AES-256-GCM, the context's UTF-8 as associated data |
| Rotation | `LocalKmsProvider` | the current key first, then the previous ones, a key listed twice tried once |
| Vault Transit | `VaultKmsProvider` | `internal::vault`, through `vectispire-cp-outbound` only (policy `INTERNAL_ALLOWED`, label `Vault KMS`, 5 s) |
| The signing key | `SigningKeyService` | `SigningKeys` over a `KeyStore` (`Settings` in the product), row `internal.document_signing_key`, context `internal:document_signing_key` |
| The contexts | `SecretCipher.*Context` | `private_key_context`, `git_token_context`, `forge_connection_context` |

**Where the key comes from is `vectispire-cp-runtime`'s.** `ENCRYPTION_KEY`, `ENCRYPTION_KEY_FILE`, the previous
keys and their file, the config tree under `/run/secrets` and the refusals (`SecretFile`, both a value and a file)
were ported with the rest of the configuration in Phase 0 (`cp-runtime/src/settings.rs`, `secret_file.rs`); a
module may not depend on the runtime. The composition (task 2.11) hands `cp_runtime::settings::Encryption` to
`EncryptionConfig` field for field, and a `VaultDoor` built from the outbound door. `tests/encryption.rs` runs
that chain from a variable naming a file to a ciphertext, as `EncryptionKeyFileDatabaseTest` does.

## Held to Java

`reference/encryption/` — written by `EncryptionReferenceSetTest` (vectispire-core) before this code, checked on
every build there and here (`tests/reference_set.rs`):

- `java-vectors.json`: sixteen configured secrets, eight contexts, four rotations, eighteen stored strings, the
  `readSecret` answers, the operators' sentences, the signing-key row with its public half, key id, a signature and
  a DSSE signature, SEC1 keys, and nineteen Transit exchanges request by request. The nonces come from a labelled
  stream: this side writes **the same bytes**, not merely readable ones.
- `rust-vectors.json`: what this side writes — ciphertexts under a raw key and a passphrase, envelopes sealed to a
  Java key (`vectispire_crypto::seal`), a signing-key row — which the Java test reads back.

What the set pinned that a reading of the code had not: Java's decoder ignores the two unused bits of a final
base64 quantum (a key or a value with them set still reads — so does it here), a missing padding reads too, the
URL-safe alphabet does not for a value but selects the URL decoder for a key, two alphabets mixed and an
over-padded key are passphrases, the spaces around a passphrase are stretched with it, bytes that are not UTF-8 read
as U+FFFD, `readSecret` trims with `String.trim` (a leading U+00A0 makes a ciphertext a "legacy clear value"),
with no current key the first previous key reads CURRENT, and a Transit answer of `42` or `null` is a ciphertext.

## Differences from Java

Decided 2026-10-17, task 2.3:

- **A secp256k1 signing key is refused at start** ("Invalid ECDSA private key format"). Java reads the curve, its
  check looks only at the field size (256), and it publishes as the public half the P-256 point of the scalar: a
  half that verifies nothing the key signs — the defect `SigningKeyService` was written against, by another road.
  The reference set records Java's answer and this side's refusal.
- **ECDSA is deterministic here** (RFC 6979); Java draws `k` at random. Either verifies against the same key, and
  the reference set checks both ways.
- **A supplied public key must be P-256** to verify a signature (`verify_with`); Java also reads a P-384 or P-521
  key a reviewer pastes. Such a key is refused as `InvalidPublicKey` (400): Vectispire signs with P-256 only, so
  the case is a third party's signature checked on Vectispire's form.
- **The private key is written as `p256` writes PKCS#8** — with the public key inside — where the JDK writes it
  without. Java reads it (`rust-vectors.json`); the stored PEM is never compared as text.
- **Vault's request bodies** carry their members in one order (`plaintext` or `ciphertext`, then `context`); Java's
  `Map.of` iterates in an order that changes between runs. Vault reads JSON.
- **A Transit answer that is not JSON** is refused with `Vault KMS encryption failed: ` and `serde_json`'s words,
  not Jackson's.
- **The body of a 200 decryption answer is not logged** when it carries no usable plaintext (Java logs it): it is
  Vault's answer to a decryption. Error bodies are logged as in Java.
- **The service is async** (`encrypt`, `inspect`, `read_secret`): Vault is a network call, and the callers are
  handlers.
