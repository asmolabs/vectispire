package com.asmolabs.vectispire.core.access.internal;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.access.GrantableTargets;
import com.asmolabs.vectispire.core.access.VisibilityService;
import java.util.NoSuchElementException;
import java.util.function.BiPredicate;
import org.springframework.stereotype.Service;

/**
 * What a grant may name, for accounts and teams alike — one rule, because the two grant tables
 * are read by one resolution in {@link VisibilityService}.
 *
 * <p><b>A target must exist when it is granted, and be one the granting administrator sees.</b> A
 * grant naming a project nobody created resolves to no repository, so it would appear on the screen
 * and grant nothing — until a project is created with that identifier, when it would quietly start
 * granting a project the administrator never chose. Only projects were checked: a repository or an
 * image id was stored whatever it was, listed as "deleted target", and waiting for the same
 * identifier to be handed out — by a restore that renumbers, since the engines themselves never
 * reuse one. Every kind is now checked, and refused as absent.
 *
 * <p><b>404, never 400 or 403, and in the same words for absent and hidden</b> — the convention of
 * {@code Visibilities.requireVisible}. The administrators who reach these routes see the whole
 * estate today, so "hidden" is not reachable by their roles; a repository or an image is checked
 * against the granter's visibility all the same, so that a role that sees less, or a credential
 * narrowed to one target, cannot grant — and so learn about — what it cannot see. A project is
 * checked for existence only: a {@code Visibility} knows the repositories a project holds, not the
 * project.
 *
 * <p><b>A grant already held is kept as it is.</b> The routes replace the set wholesale, and the
 * screen sends back every grant it listed, the ones whose target went included; refusing those would
 * make an account whose repository was deleted before grants were revoked with their target
 * uneditable until somebody found the row. Keeping one creates nothing that was not already there.
 */
@Service
public class GrantTargets {

    private final GrantableTargets targets;

    public GrantTargets(GrantableTargets targets) {
        this.targets = targets;
    }

    /**
     * The kind normalized, or a refusal naming what is wrong with the grant.
     *
     * @param granter what the administrator granting may see
     * @param held whether the grantee holds this grant already, before the replacement — asked with
     *     the kind normalized, as the grant tables store it
     * @throws IllegalArgumentException for a kind that does not exist — a malformed request, 400
     * @throws NoSuchElementException for a target that does not exist or that the granter does not
     *     see — 404, in the same words
     */
    public String validate(String kind, Long id, Visibility granter, BiPredicate<String, Long> held) {
        String normalized = TeamRules.validateTargetKind(kind);
        if (held.test(normalized, id)) {
            return normalized;
        }
        boolean grantable = switch (normalized) {
            case TeamRules.KIND_PROJECT -> targets.projectExists(id);
            case TeamRules.KIND_REPOSITORY -> visible(new ScanTarget.Repository(id), granter);
            case TeamRules.KIND_CONTAINER -> visible(new ScanTarget.Container(id), granter);
            default -> false;
        };
        if (!grantable) {
            throw new NoSuchElementException("No " + normalized + " with id " + id + ".");
        }
        return normalized;
    }

    private boolean visible(ScanTarget target, Visibility granter) {
        return targets.exists(target) && granter.permits(target);
    }
}
