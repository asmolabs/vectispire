-- The platform governor's waiver of the signature requirement, one plugin at a time.
--
-- From 2026-09-30 an executor runs a plugin only if its manifest declares a signer and cosign
-- verifies the image (decision 0017 §9), unless the governor waived the requirement for that plugin,
-- in writing. The waiver is the registry's, not the manifest's: it says the platform accepts running
-- this plugin unsigned, and takes nothing away from a signer a manifest declares, which is verified
-- all the same. Kept on the plugin rather than in the manifest so that granting or revoking it is a
-- gesture of its own, audited as such, and not a new manifest digest every stored task would miss.
--
-- `unsigned_waiver` is the justification — 20 to 500 characters, as a network exception's — and
-- null means no waiver; `unsigned_waived_by` and `unsigned_waived_at` say who granted the one in
-- force. Revoking clears the three; the audit log keeps the history.
--
-- Written once, in common: added nullable columns, one statement each, since SQLite adds one column
-- per `alter table`.

alter table t_plugin add column unsigned_waiver varchar(500);
alter table t_plugin add column unsigned_waived_by varchar(255);
alter table t_plugin add column unsigned_waived_at ${ts};
