-- The SIEM authorization header is encrypted from now on, and ciphertext is longer than its text.
--
-- The header was stored as typed, the one credential in the schema that did not go through
-- `EncryptionService`. AES-GCM adds a 12-byte nonce and a 16-byte tag, and Base64 inflates the
-- whole by a third: at 512 characters the column would have capped a header at about 350, fewer
-- than a signed JWT carries. 2048 leaves a header of about 1500.
--
-- Rows already stored in the clear keep working: `EncryptionService.readSecret` accepts them and
-- warns on every read until the configuration is saved again.

-- Nothing to alter on SQLite: it does not enforce a varchar length, so the ciphertext already
-- fits, and changing a column type there means rebuilding the table for no effect.

select 1;
