package com.asmolabs.vectispire.core.plugins;

/**
 * A port {@code plugins} declares for a module above it that reacts to a report accepted for a
 * repository — a SARIF document, a coverage report, a test report — the checklists, whose measured lines
 * the report may now answer (decision 0032, amendment "the scans answer the lines they measure").
 *
 * <p><b>Called inside the import's transaction, and only to queue</b> (decision 0033), as
 * {@code scanning.RepositoryScanned} is for a scan: what reacts commits with the import or not at all,
 * where a call after the commit lost the reaction to a stop in between. An implementation writes only in
 * the caller's transaction — an outbox message — and does its work later; anything it throws rolls the
 * import back, which is why it must do nothing that can fail for a reason of its own.
 */
public interface RepositoryReported {

    /** A report about this repository was accepted; called in the import's transaction, before it commits. */
    void reported(long repositoryId);
}
