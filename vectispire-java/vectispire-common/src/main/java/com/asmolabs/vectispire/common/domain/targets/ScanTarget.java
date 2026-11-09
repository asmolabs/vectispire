package com.asmolabs.vectispire.common.domain.targets;

import java.util.Optional;

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

    /** A repository, as a grant, an API key's restriction, a policy route or an export names it. */
    String KIND_REPOSITORY = "repository";

    /** A container image, likewise. */
    String KIND_CONTAINER = "container";

    record Repository(long id) implements ScanTarget {}

    record Container(long id) implements ScanTarget {}

    /**
     * The target a kind and an identifier name, or empty for any other kind.
     *
     * <p>Exact and case-sensitive: a kind is normalised where it enters, never guessed here. Empty
     * rather than a refusal because what an unknown kind means is the caller's — a grant that grants
     * nothing, a key that sees nothing, a route that answers 400 — and the seven places that parsed
     * the string each decided it for themselves, most of them by comparing literals.
     */
    static Optional<ScanTarget> of(String kind, long id) {
        if (KIND_REPOSITORY.equals(kind)) {
            return Optional.of(new Repository(id));
        }
        if (KIND_CONTAINER.equals(kind)) {
            return Optional.of(new Container(id));
        }
        return Optional.empty();
    }

    /**
     * The target of a row carrying both columns: the repository when it has one, the container
     * otherwise, and {@code null} for a row attached to neither — which each caller files nowhere.
     */
    static ScanTarget ofColumns(Long repoId, Long containerId) {
        if (repoId != null) {
            return new Repository(repoId);
        }
        return containerId == null ? null : new Container(containerId);
    }

    /** The inverse of {@link #of(String, long)}. */
    default String kind() {
        return switch (this) {
            case Repository r -> KIND_REPOSITORY;
            case Container c -> KIND_CONTAINER;
        };
    }

    /**
     * The stable text form that enters an issue's fingerprint — {@code repo:7}, {@code container:3}.
     * Not the {@link #kind()}: the fingerprint's spelling is a data contract of its own.
     */
    default String fingerprintKey() {
        return switch (this) {
            case Repository r -> "repo:" + r.id();
            case Container c -> "container:" + c.id();
        };
    }

    /** The inverse of {@link #fingerprintKey()}, or empty for a key it never wrote. */
    static Optional<ScanTarget> fromFingerprintKey(String key) {
        int colon = key.indexOf(':');
        if (colon < 0) {
            return Optional.empty();
        }
        long id;
        try {
            id = Long.parseLong(key.substring(colon + 1));
        } catch (NumberFormatException malformed) {
            return Optional.empty();
        }
        return switch (key.substring(0, colon)) {
            case "repo" -> Optional.of(new Repository(id));
            case "container" -> Optional.of(new Container(id));
            default -> Optional.empty();
        };
    }
}
