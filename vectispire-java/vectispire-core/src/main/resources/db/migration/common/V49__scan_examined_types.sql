-- The built-in finding types a scan actually examined — decision 0032, §6.
--
-- `ScanIngestor` has always computed the set: a type is in it if and only if its step produced
-- (decision 0007 — absent is not empty), and it is what the backlog resolves against. It was then
-- discarded, so nothing could say afterwards whether a completed scan's secret detection had run or
-- had failed and left the type alone; the step's failure survived only as a sentence in `error`.
-- A checklist line asking "was this tree searched for secrets within seven days" needs the answer
-- from the scan itself.
--
-- The wire names of the types, comma-separated and sorted (`iac,license,secret`), as the key scopes
-- and the agents' labels are kept. Empty for a scan written after the upgrade in which no step
-- produced. Null on every row already stored, and null means "examination unrecorded" — never
-- "examined nothing": a scan from before the upgrade looked at whatever it looked at, and nothing
-- recorded what. The plugins' outcomes stay in `plugin_steps`, in their three states.
--
-- 255 characters: the seven built-in types spelled out take fifty.
--
-- Written once, in common: an added nullable column.

alter table t_scan add column examined_types varchar(255);
