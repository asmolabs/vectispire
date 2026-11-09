-- The identifiers of the findings an OWASP report's model was shown, kept as a JSON array of strings.
--
-- The report's screen links what the model cites to the backlog, and may link only what the model was
-- shown: a CVE the model invented, or one a finding's description carried in from the audited
-- repository, is not a finding, and a link would present it as one. The shown findings are already in
-- `inputs` — as prose for the model, a table whose cells the data itself may contain the separator of,
-- so reading them back from it is a parser of our own output that a crafted identifier can mislead.
-- Recomputing them from the backlog is wrong for the reason V31 kept `inputs`: the issues have moved on.
--
-- Null on every row already stored: those reports recorded no identifier set, and their links read as
-- not recorded rather than as none.
--
-- Written once, in common: an added nullable column. V83 is the integration registry's, written on
-- another branch.

alter table t_ai_review_result add column evidence_identifiers ${text};
