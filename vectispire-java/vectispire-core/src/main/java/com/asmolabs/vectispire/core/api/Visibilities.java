package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.services.access.RowVisibility;

/**
 * The routes' name for {@link RowVisibility}, which holds the rule and its reasons: 404 never 403,
 * and one sentence for an absent row and a hidden one.
 *
 * <p><b>A delegate, not a copy.</b> It is kept, rather than every route calling {@code
 * RowVisibility} directly, because {@code AuthorizationCoverageTest} and {@code RouteScopingTest}
 * read controller source for {@code Visibilities.} to decide that a route resolves an allowance.
 * Renaming the call would mean widening those lints, and a lint widened to follow a rename is how
 * one ends up matching something that is not a check at all.
 */
final class Visibilities {

    private Visibilities() {}

    static void requireVisible(ScanTarget target, Visibility visibility) {
        RowVisibility.requireVisible(target, visibility);
    }
}
