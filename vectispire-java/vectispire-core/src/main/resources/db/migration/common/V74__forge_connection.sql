-- Forge connections — decision 0037 §2, lot D1: a read-only credential to a GitHub or GitLab, from which
-- repositories will be discovered (D3) and imported as ordinary targets (D6).
--
-- Written once, in common: a new table, no foreign key in or out. The discovery's snapshot and the
-- imported targets' provenance (D3, D6) will hang on this row from tables of the same module; nothing
-- outside `forges` will ever point at it.
--
-- `token` holds a ciphertext (`v2:` + base64 of nonce, text and tag, or Vault's `vault:v1:`), encrypted
-- with the row as context, never a token: bounded at 1,024 characters before encryption, the ciphertext
-- stays under 1,500. `ca_pem` is public — a CA bundle pinned for this server alone, in place of the
-- runtime's trust store — and stored as written. `base_url` is the web address, the API's root is derived
-- from it; `owner` is GitHub's (the organisation or user the token was issued for), null for GitLab.
--
-- What the forge said about the token at the last probe: `credential_kind`, `scopes` (comma-separated,
-- null when the forge does not report them — a GitHub fine-grained token), `can_write` (null when not
-- reported: unknown is not "no"), `token_expires_at` (null when none was reported) and `forge_version`
-- (null for the clouds, which do not state one).
create table t_forge_connection (
    id char(36) not null primary key,
    name varchar(255) not null,
    kind varchar(20) not null,
    edition varchar(40) not null,
    base_url varchar(512) not null,
    owner varchar(100),
    internal_network ${bool} not null,
    ca_pem ${text},
    token varchar(2048) not null,
    credential_kind varchar(40) not null,
    scopes varchar(1000),
    can_write ${bool},
    token_expires_at ${ts},
    forge_version varchar(64),
    probed_at ${ts} not null,
    created_at ${ts} not null,
    created_by varchar(255) not null,
    updated_at ${ts} not null,
    updated_by varchar(255) not null,
    constraint uq_forge_connection_name unique (name)
);
