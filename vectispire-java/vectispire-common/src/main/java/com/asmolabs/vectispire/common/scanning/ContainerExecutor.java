package com.asmolabs.vectispire.common.scanning;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;

/**
 * What a scan needs to run its scanners: one {@link ContainerRun} at a time, in the closed shape it
 * describes, and an image exported for the cataloguer to read.
 *
 * <p><b>The seam of decision 0045.</b> {@link ContainerRunner} runs each request as a Docker
 * container; on a cluster without Docker, the agent runs each one as a pod in a namespace of its own.
 * Every scanner, the vulnerability database, the signature check and the plugins take this interface,
 * so the backend is chosen once, where the agent is composed, and nothing that reads a scanner's output
 * knows which one ran it.
 *
 * <p><b>The contract is the closed shape, not Docker.</b> An implementation runs the request with no
 * capability, no new privilege, a read-only root filesystem, as the user the request names, with no
 * network unless the request asks for it, within the limits and the timeout, in a fresh container
 * removed after the run; and it fails — {@link ScannerFailureException}, never an empty result — when
 * it cannot (decision 0007). What a backend cannot express exactly is written in its own class, with the
 * compensation that stands in for it.
 *
 * <p>The result types are {@link ContainerRunner}'s, for now: moving them is a change of its own.
 */
public interface ContainerExecutor {

    /**
     * The ceiling on what a scanner may hand back, in bytes — its standard output, and the report file a
     * plugin writes, which is the same output by another route and gets the same bound.
     */
    long outputBytes();

    /** How long a scanner may run before it is stopped — what a scan that started can still take. */
    Duration scannerTimeout();

    /**
     * Can it run anything at all?
     *
     * <p><b>Asked before a claim.</b> A worker whose executor cannot run anything used to claim the scan all
     * the same, and the steps that needed it failed on the scan with the executor's own reason — an attempt
     * spent per claim, for a fault that was the worker's. The worker now says what this answers, the claim
     * hands it nothing its available executors cannot run, and the agents screen shows the reason — see
     * {@code WorkerExecutors}.
     */
    default boolean isAvailable() {
        return whyUnavailable().isEmpty();
    }

    /**
     * Why it cannot run anything now, in its own words, or empty when it can. Asked as often as a worker
     * polls, so as cheap as the backend allows: a ping, a listing.
     */
    Optional<String> whyUnavailable();

    /**
     * Whether {@link #exportImage} works on this backend, and so whether a worker using it can scan a container
     * image at all. A backend that cannot says so here rather than only failing the export: the claim reads
     * this, so a scan it would fail is never handed to it.
     */
    default boolean exportsImages() {
        return true;
    }

    /**
     * Writes {@code reference}, for {@code platform}, to {@code destination} as an archive the cataloguer
     * reads offline. The platform is mandatory: without it a registry answers with the executor's own
     * architecture, and the inventory is of a variant nobody asked to audit.
     */
    void exportImage(String reference, String platform, Path destination);

    /** Runs one request in the closed shape and returns what it wrote, or fails naming the step. */
    ContainerRunner.ContainerResult run(ContainerRun request);

    /**
     * What this executor holds to read {@code reference}'s registry — the registry as its pulls key it,
     * and whether it carries credentials for it, never the credentials — so a tool's refusal can say which
     * of "none held" and "the ones held were refused" it was.
     */
    ContainerRunner.RegistryAccess registryAccessFor(String reference);
}
