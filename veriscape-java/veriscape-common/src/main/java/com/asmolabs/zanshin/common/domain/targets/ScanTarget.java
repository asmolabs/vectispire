package com.asmolabs.zanshin.common.domain.targets;

/**
 * What a scan runs against: a source repository, or a container image.
 *
 * <p>A sealed interface rather than two nullable identifiers. The NestJS version carried
 * {@code repoId} and {@code containerId} side by side with a comment saying they are mutually
 * exclusive, and every consumer had to remember that — including the fingerprint, which got it
 * right only because it tested {@code != null} rather than truthiness, so that repository
 * {@code 0} did not silently file itself as a container.
 *
 * <p>Here the compiler carries the rule, and the class of bug the comment was guarding against
 * cannot be written.
 */
public sealed interface ScanTarget {

    record Repository(long id) implements ScanTarget {}

    record Container(long id) implements ScanTarget {}

    /** The stable text form that enters an issue's fingerprint. */
    default String fingerprintKey() {
        return switch (this) {
            case Repository r -> "repo:" + r.id();
            case Container c -> "container:" + c.id();
        };
    }
}
