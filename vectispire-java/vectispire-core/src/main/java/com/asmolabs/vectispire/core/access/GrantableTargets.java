package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * What {@code access} needs to know about the targets it grants: which exist, what they are called,
 * and which repositories a project holds today.
 *
 * <p><b>A port, implemented by {@code targets}.</b> Visibility resolves a project grant into the
 * project's repositories at each request, a grant is validated against what exists, and the grant
 * and key screens name what they list. {@code access} read the targets' tables for all of it while
 * {@code targets} filtered its lists through {@code access} — and every route of every module uses
 * {@code access}, so it has to stay below all of them. Declared here with the four questions it asks,
 * the dependency points from {@code targets} to {@code access} and nowhere else (decision 0029).
 */
public interface GrantableTargets {

    /** A grant as the account and team administration hold one: a kind and an identifier. */
    interface Grant {
        String kind();

        Long id();
    }

    /**
     * A grant as a screen lists it.
     *
     * <p>Named by the server rather than left to the client to look up. The client used to label a
     * grant from the list of repositories and images it fetched for the selector; a project is in
     * neither, so a project grant would have been listed as a bare number — or, worse, not at all, on
     * the screen whose job is to say what somebody can read.
     *
     * @param name what the target is called now, "deleted target" when it no longer exists — a grant
     *     row outliving its target is worth seeing rather than hiding
     */
    record TargetGrant(String kind, Long id, String name) {}

    /** The grants, in the order given, each with its target's name. */
    List<TargetGrant> named(List<? extends Grant> grants);

    /** The repositories filed in these projects, as they are now. Never asked with an empty set. */
    List<Long> repositoriesIn(Collection<Long> projectIds);

    boolean projectExists(long projectId);

    boolean exists(ScanTarget target);

    /**
     * Every repository and image with its display name, each map in the order the targets were
     * created — the order the key screen lists them in.
     */
    Labels labels();

    record Labels(Map<Long, String> repositories, Map<Long, String> containers) {}
}
