-- The languages the Semgrep rules handed to a scan read.
--
-- A checklist line on the built-in static analysis (`builtin:sast`, `builtin:quality`) passed on a
-- repository whose SAST step produced and found nothing — even when none of the rules it ran with
-- read any language of the tree: nothing found, because nothing was read. Comparing the tree's
-- languages (`detected_languages`, V57) with the rules' needs the rules' languages as they were when
-- the scan ran. Read from whatever set is active when somebody opens the checklist, a set activated
-- afterwards would claim, for a scan that never had it, coverage it never gave.
--
-- Written by the control plane when it builds the task — the one place that decides which rules a
-- scan carries, for the built-in worker and every agent alike: the bundled rules' languages and the
-- active set's, by the catalogue directories their files came from, as `Language`'s wire names,
-- sorted and comma-separated. Null on every row already stored, on an image scan, and on a scan asked
-- to run no SAST step: null means "not recorded", never "reads nothing" (decision 0007).
--
-- 512 characters, as `detected_languages`: the twenty-four languages spelled out take 154.
--
-- Written once, in common: an added nullable column.

alter table t_scan add column sast_languages varchar(512);
