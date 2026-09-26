package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.repositories.Projects;
import org.springframework.stereotype.Service;

/**
 * What a grant may name, for accounts and teams alike — one rule, because the two grant tables
 * are read by one resolution in {@link VisibilityService}.
 *
 * <p><b>A project must exist when it is granted.</b> A grant naming a project nobody created
 * resolves to no repository, so it would appear on the screen and grant nothing — until a project
 * is created with that identifier, when it would quietly start granting a project the
 * administrator never chose. Refused as a 400 rather than stored.
 */
@Service
public class GrantTargets {

    private final Projects projects;

    public GrantTargets(Projects projects) {
        this.projects = projects;
    }

    /** The kind normalized, or a refusal naming what is wrong with the grant. */
    public String validate(String kind, Long id) {
        String normalized = TeamRules.validateTargetKind(kind);
        if (TeamRules.KIND_PROJECT.equals(normalized) && !projects.existsById(id)) {
            throw new IllegalArgumentException("No project with id " + id + ".");
        }
        return normalized;
    }
}
