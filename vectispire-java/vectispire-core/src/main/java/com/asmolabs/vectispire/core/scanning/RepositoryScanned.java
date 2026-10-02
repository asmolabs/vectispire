package com.asmolabs.vectispire.core.scanning;

/**
 * A port {@code scanning} declares for a module above it that reacts to a repository's completed scan —
 * the checklists, whose measured lines the scan may now answer (decision 0032, amendment "the scans
 * answer the lines they measure").
 *
 * <p><b>Called inside the scan's transaction, and only to queue.</b> The dispatcher calls it as the
 * completed result of a repository's scan is written, whichever executor ran it, so that what reacts
 * commits with the scan or not at all (decision 0033): called after the commit, a process stopping in
 * between answered nothing for that scan. An implementation writes only in the caller's transaction —
 * an outbox message — and does its work later, where a failure is retried; anything it throws here
 * rolls the scan's results back, which is why it must do nothing that can fail for a reason of its own.
 */
public interface RepositoryScanned {

    /** A scan of this repository completed; called in its transaction, before it commits. */
    void scanned(long repositoryId);
}
