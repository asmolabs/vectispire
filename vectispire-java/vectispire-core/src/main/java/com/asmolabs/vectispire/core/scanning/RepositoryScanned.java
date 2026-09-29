package com.asmolabs.vectispire.core.scanning;

/**
 * A port {@code scanning} declares for a module above it that reacts to a repository's completed scan —
 * the checklists, whose measured lines the scan may now answer (decision 0032, amendment "the scans
 * answer the lines they measure").
 *
 * <p><b>Called after the scan's own commit, and never able to fail it.</b> The dispatcher calls it once
 * the result is written and committed, for a completed scan of a repository — whichever executor ran it —
 * and catches whatever it throws: a scan does not fail, nor go back to the queue, because a checklist
 * could not be answered. Inside the scan's transaction a reaction would hold the scan's row lock for as
 * long as it took, and its failure would roll the results back. The cost accepted: a process that stops
 * between the commit and the call answers nothing for that scan — the next scan, import or opening does,
 * from the same evidence.
 */
public interface RepositoryScanned {

    /** A scan of this repository completed and is committed. */
    void scanned(long repositoryId);
}
