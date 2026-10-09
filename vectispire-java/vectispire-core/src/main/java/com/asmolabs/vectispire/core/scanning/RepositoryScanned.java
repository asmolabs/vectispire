package com.asmolabs.vectispire.core.scanning;

/**
 * A port {@code scanning} declares for the modules above it that react to a repository's completed scan —
 * the checklists, whose measured lines the scan may now answer (decision 0032, amendment "the scans
 * answer the lines they measure"), and the OWASP report an operator asked to have written after each
 * scan ({@code compliance}). Every implementation is told, in no promised order: none of them reads
 * what another queues.
 *
 * <p><b>Called inside the scan's transaction, and only to queue.</b> The dispatcher calls it as the
 * completed result of a repository's scan is written, whichever executor ran it, so that what reacts
 * commits with the scan or not at all (decision 0033): called after the commit, a process stopping in
 * between answered nothing for that scan. An implementation writes only in the caller's transaction —
 * an outbox message — and does its work later, where a failure is retried; anything it throws here
 * rolls the scan's results back, which is why it must do nothing that can fail for a reason of its own.
 */
public interface RepositoryScanned {

    /**
     * A scan of this repository completed; called in its transaction, before it commits.
     *
     * @param scanId the scan that completed — what a reaction built from it names as its source
     */
    void scanned(long repositoryId, long scanId);
}
