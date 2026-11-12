-- Which of the tracked branches each discovered repository has — decision 0037 §3–5: `main`, `master` and
-- `develop` unless `vectispire.forges.discovery.tracked-branches` names others. The selection filters on them, and
-- an import naming branches creates one target per branch the repository has.
--
-- `tracked_branches` holds the names a discovery found, sorted and comma-separated: the empty text when it found
-- none of them, null when the forge did not answer for every one — a Guest who may not read the code, an error —
-- and for every row this upgrade finds. Unknown is not none (0007): an import never creates a target on a branch
-- nobody saw, and the filter counts the unknown apart. `branches_asked` is the list the reading asked, so that a
-- name tracked since is unknown rather than absent and is asked at the next run; `branches_read_activity_at` the
-- repository's last activity at the reading, so that a repository active since is asked again — the language's
-- own rule, but kept per column, since a reading cut short by a rate limit must not pass for done.
--
-- Width: ten names of at most 255 characters and their nine commas.
--
-- Written once, in common: three nullable columns of types the placeholders spell, nothing to fill.
alter table t_forge_repository add column tracked_branches varchar(2600);
alter table t_forge_repository add column branches_asked varchar(2600);
alter table t_forge_repository add column branches_read_activity_at ${ts};
