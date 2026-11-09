-- The report documents' standing — decision 0035 §4, lot R7: a holder asks by SHA-256 whether this installation
-- still stands by a document, and a manifest's withdrawal is applied to every document it produced.
--
-- Written once, in common: indexes only. Nothing is copied onto the documents: a document's withdrawal is its
-- manifest's, read through the run's `manifest_digest` from `t_report_plugin_manifest` — one row the governor
-- writes, so no document can be left unmarked by a withdrawal that raced the run producing it, and nothing is
-- rewritten when a manifest is withdrawn.

-- The status route looks a document up by the package a download hands out, or by the file inside it — the
-- provenance's subject, which is what a recipient holds once the package is opened. The run's row, not the
-- document's: it keeps both digests past the evidence window, when the bytes are gone and copies are still in
-- the world.
create index idx_report_run_package on t_report_run (package_sha256);
create index idx_report_run_output on t_report_run (output_sha256);

-- A withdrawal counts the documents it withdraws, in its audit entry.
create index idx_report_run_manifest on t_report_run (manifest_digest);
