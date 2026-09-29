package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * What the target screens need from the scan queue: each target's latest scan, and a scan queued on
 * request.
 *
 * <p><b>A port, implemented by {@code scanning}.</b> The repository and image administration read
 * the scans table for their listings and called {@code ScanTriggerService} for the "scan now"
 * button, while {@code scanning} reads the targets' rows to clone and to schedule — {@code targets}
 * and {@code scanning} used each other. The direction kept is {@code scanning} → {@code targets}: a
 * scan is of a target, and the purge of a deleted target is an event {@code scanning} must hear
 * (decision 0029). What {@code targets} still needs of the queue is asked here, and answered by the
 * module that owns it.
 */
public interface TargetScans {

    /** A target's most recent scan, as the listings show it beside the row. */
    record LatestScan(Long id, String status, Instant createdAt, String error) {}

    /** A scan just queued: what the "scan now" route answers. */
    record Queued(Long id, String status) {}

    /** The latest scan of every repository that has one, keyed by repository. */
    Map<Long, LatestScan> latestPerRepository();

    /** The latest scan of every image that has one, keyed by image. */
    Map<Long, LatestScan> latestPerContainer();

    /**
     * The languages each of these repositories' newest completed scan found in its tree, in the
     * plugin manifests' vocabulary ({@link Language}'s wire names). A repository missing from the answer
     * is <b>unknown</b> — no completed scan, or a newest one that recorded no whole census — which a
     * screen must never show as "no language"; an empty set is "counted, and none" (decision 0007).
     * Batched by the implementation: the list is sized by the estate.
     */
    Map<Long, Set<Language>> detectedLanguages(Collection<Long> repositoryIds);

    /**
     * Queues a scan of the repository as it stands now — branch, sub-path and required label copied
     * onto the scan — or refuses when one is already waiting.
     */
    Queued queue(RepositoryView repository);

    /** The same for an image. */
    Queued queue(ContainerView container);
}
