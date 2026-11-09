-- The namespaces a discovery could not read with its connection's token — decision 0037 §3, lot D4.
--
-- GitHub lists an organisation's repositories one organisation at a time, and answers 403 for one the token
-- is refused — single sign-on not authorised, an IP allow list, a policy against this kind of token. The run
-- goes on with the others and ends completed; what it could not read is recorded here, and none of those
-- namespaces' repositories is marked gone by it: a refusal is not an absence. One per line, the namespace and
-- the reason separated by a tab, an empty namespace for those the forge withheld without naming them; null for
-- a run that read everything — every run stored before this version.
--
-- Written once, in common: an added nullable column.

alter table t_forge_discovery add column unreadable_namespaces ${text};
