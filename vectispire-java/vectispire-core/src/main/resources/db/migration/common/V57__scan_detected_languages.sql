-- The languages a scan's census found in the tree it examined.
--
-- The census (`LanguageCensus`) has run inside every scan with a plugin since decision 0017, to tell
-- a plugin that does not apply from one that did not run, and its answer was then dropped: no screen
-- could put "this project's repositories are Java and TypeScript" beside the languages a plugin
-- declares, nor a checklist tell a language that was analysed from one nobody looked at.
--
-- The wire names of `Language` — the vocabulary a plugin manifest declares, the Semgrep catalogue's
-- directories — sorted and comma-separated (`java,typescript`), as `examined_types` is kept. Empty
-- for a census that walked the whole tree and saw no file naming a language. Null on every row
-- already stored, on an image scan (no tree), and wherever the census stopped short of the end of the
-- tree: null means "unknown", never "no language" (decision 0007).
--
-- 512 characters: the twenty-four languages spelled out take 154.
--
-- Written once, in common: an added nullable column.

alter table t_scan add column detected_languages varchar(512);
