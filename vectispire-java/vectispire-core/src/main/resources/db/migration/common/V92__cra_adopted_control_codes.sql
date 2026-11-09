-- The CRA's control codes, renumbered from the 2022 proposal to Regulation (EU) 2024/2847 as adopted
-- (decision 0046 §1).
--
-- The codes named the proposal's Art. 10 and Art. 11 while the titles beside them cited Art. 13, Art. 14
-- and Annex I, so an auditor read `CRA-ART10-VULN` next to "Annex I, Part II (2)". The catalogue in
-- `ComplianceFramework.EU_CRA` now carries the adopted numbering, and a declaration is matched to its
-- control by code: left as it was, every CRA line of the statement of applicability would be read as a
-- control this build does not carry, dropped, and its control shown undeclared — the organisation's
-- decision gone from the document without a word.
--
-- `t_control_declaration.control_id` is the one column that stores them. The monthly snapshot keeps
-- counts per framework, not per control, and a checklist's `control` is the imported template's own
-- text. The audit log keeps the old codes in the entries written before this: they are what was
-- recorded then, and the chain those entries are hashed into is not rewritten.
--
-- The (framework, control_id) unique index is not expected to be hit: since 0.10 the declaration route
-- refuses a code the catalogue does not name, so no release could store a new code beside its old one.
-- A row typed with one by hand before 0.10 would stop this migration, and the startup with it, which is
-- the right outcome for a declaration that says two things about one control.
--
-- Written once, in common: plain updates every engine spells alike.

update t_control_declaration set control_id = 'CRA-ART14-NOTIF'
    where framework = 'EU_CRA' and control_id = 'CRA-ART11-NOTIF';
update t_control_declaration set control_id = 'CRA-ANNEX1-SBOM'
    where framework = 'EU_CRA' and control_id = 'CRA-ART10-SBOM';
update t_control_declaration set control_id = 'CRA-ART13-LIFECYCLE'
    where framework = 'EU_CRA' and control_id = 'CRA-ART10-LIFECYCLE';
update t_control_declaration set control_id = 'CRA-ANNEX1-VULN'
    where framework = 'EU_CRA' and control_id = 'CRA-ART10-VULN';
