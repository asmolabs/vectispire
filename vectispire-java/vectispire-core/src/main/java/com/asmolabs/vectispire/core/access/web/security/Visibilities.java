package com.asmolabs.vectispire.core.access.web.security;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.RowVisibility;

/**
 * The routes' name for {@link RowVisibility}, which holds the rule and its reasons: 404 never 403,
 * and one sentence for an absent row and a hidden one.
 *
 * <p><b>A delegate, not a copy.</b> It is kept, rather than every route calling {@code
 * RowVisibility} directly, because {@code AuthorizationCoverageTest} and {@code RouteScopingTest}
 * read controller source for {@code Visibilities.} to decide that a route resolves an allowance.
 * Renaming the call would mean widening those lints, and a lint widened to follow a rename is how
 * one ends up matching something that is not a check at all.
 *
 * <p><b>Public since the controllers started leaving {@code core.api}</b> for their modules' {@code
 * web} packages (decision 0028): package-private, it could only be called by the controllers that
 * had not moved.
 */
public final class Visibilities {

    private Visibilities() {}

    public static void requireVisible(ScanTarget target, Visibility visibility) {
        RowVisibility.requireVisible(target, visibility);
    }
}
