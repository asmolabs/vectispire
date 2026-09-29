package com.asmolabs.vectispire.core.plugins;

/**
 * A port {@code plugins} declares for a module above it that reacts to a report accepted for a
 * repository — a SARIF document, a coverage report, a test report — the checklists, whose measured lines
 * the report may now answer (decision 0032, amendment "the scans answer the lines they measure").
 *
 * <p><b>Called after the import's own commit and its audit entry, and never able to fail it.</b> The
 * pipeline that deposited the report is answered for the import it made, whatever the reaction does: a
 * failure is logged and swallowed by the caller. The cost accepted: a process that stops between the
 * commit and the call answers nothing for that report — the next scan, import or opening does.
 */
public interface RepositoryReported {

    /** A report about this repository was accepted and is committed. */
    void reported(long repositoryId);
}
