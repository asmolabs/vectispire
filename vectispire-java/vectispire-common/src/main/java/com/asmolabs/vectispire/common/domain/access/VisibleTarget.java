package com.asmolabs.vectispire.common.domain.access;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.Objects;

/**
 * A target the caller's {@link Visibility} was asked about, and permitted.
 *
 * <p><b>The proof a service takes when it may not decide itself.</b> The services of {@code exports},
 * {@code inventory} and {@code gate} do not use {@code access} ({@code
 * ArchitectureTest.accessForRoutesOnly}), so the refusal — its one sentence, 404 never 403 — stays at
 * their routes. Their methods taking a bare id trusted every caller to have refused first: the route
 * that did, and whichever route, task or neighbouring service reached the same method next and did
 * not. A method taking this instead cannot be called with a target nobody checked.
 *
 * <p><b>Minted by the guard alone.</b> Java cannot restrict a constructor to another package, so
 * {@code ArchitectureTest.visibleTargetsAreMintedByTheGuard} does: only {@code RowVisibility}, having
 * refused a hidden target, builds one. A {@code new VisibleTarget<>(…)} anywhere else is the check
 * skipped under another name.
 *
 * <p>Generic in the kind, so a method that reads a repository's API inventory takes a {@code
 * VisibleTarget<ScanTarget.Repository>} and a container cannot be handed to it.
 */
public record VisibleTarget<T extends ScanTarget>(T target) {

    public VisibleTarget {
        Objects.requireNonNull(target, "target");
    }
}
