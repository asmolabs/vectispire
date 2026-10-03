-- The identity of a repository target, and the database's refusal of a second one — decision 0037, §4.
--
-- Written once, in common: two columns and two indexes, no foreign key, the same on both engines.
--
-- `url_identity` is `RepositoryUrl.identity` of the URL — `host/path`, lower case, without scheme, user,
-- port or `.git` — which discovery compares whatever the target's branch and sub-path. Indexed, not
-- unique: one repository is legitimately several targets (two directories of a monorepo, two branches).
--
-- `identity_guard` is the SHA-256 of the identity, the branch and the sub-path (`RepositoryIdentity`):
-- the target itself, held unique so that two creations racing past the service's check cannot both
-- commit. A hash because the three parts are up to 765 characters, past what one MySQL index holds, and
-- because a null sub-path would escape a composite key on both engines.
--
-- **Both null on every row this migration finds, on purpose.** The identity is computed in Java — the
-- parsing of three URL forms has no portable SQL spelling — so the rows are keyed after the start by
-- `RepositoryIdentityTask`, oldest first. And an installation may already hold the same target twice:
-- a unique index filled here would refuse to build on it and stop the upgrade, and deleting either row
-- would destroy its backlog and its triage. Nulls are distinct in a unique index on PostgreSQL and on
-- MySQL, so the oldest row of a pair takes the guard and the others keep null — still served, still
-- scanned, refused nothing, and listed at `GET /api/v1/repositories/duplicates` for an administrator to
-- merge by hand.
alter table t_repository add column url_identity varchar(255);
alter table t_repository add column identity_guard varchar(64);

create unique index uq_repository_identity_guard on t_repository (identity_guard);
create index idx_repository_url_identity on t_repository (url_identity);
