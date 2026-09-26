package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.core.access.persistence.ApiKeyRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetRepository;
import com.asmolabs.vectispire.core.access.persistence.UserTargetRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The grants naming one target, to accounts and to teams, revoked together.
 *
 * <p><b>Why anybody outside {@code access} needs this.</b> A grant names its target as {@code (kind,
 * id)}, which no foreign key can follow into three tables, so nothing cascades: whoever deletes a
 * repository, an image or a project has to revoke what names it, or the row stays on the grant
 * screens — and, should an engine hand the identifier out again, grants a target nobody chose (see
 * {@link UserTargetRepository#deleteByTarget}). The deleting module used to write both grant tables itself
 * (a step-5 finding of decision 0028); it now asks here.
 */
@Service
public class TargetGrants {

    private final UserTargetRepository userTargets;
    private final TeamTargetRepository teamTargets;
    private final ApiKeyRepository keys;

    public TargetGrants(UserTargetRepository userTargets, TeamTargetRepository teamTargets, ApiKeyRepository keys) {
        this.userTargets = userTargets;
        this.teamTargets = teamTargets;
        this.keys = keys;
    }

    /**
     * Revokes every grant naming the target and says how many went — and the integration keys
     * restricted to it, which are a grant of the same shape.
     *
     * <p>{@code MANDATORY}: the revocation belongs to the deletion that causes it. Committed on its
     * own, a deletion that then rolled back would leave its target standing and its grants gone.
     *
     * <p><b>The keys too.</b> A key restricted to a repository names it as {@code (kind, id)} like a
     * grant, and was left behind by the deletion: useless while the identifier stays unused — the
     * supported engines never reuse one — and pointed at somebody else's target the day a restore
     * renumbers. Here rather than in a listener of {@code TargetDeleted}: {@code access} sits below
     * {@code targets}, so the publisher calls it before the first phase, as it calls for the grants.
     * An agent's key is not revoked: it belongs to its agent.
     *
     * @param kind as the grant tables store it — {@code TeamRules.KIND_REPOSITORY}, {@code
     *     KIND_CONTAINER} or {@code KIND_PROJECT}
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public int revokeAll(String kind, long targetId) {
        return userTargets.deleteByTarget(kind, targetId)
                + teamTargets.deleteByTarget(kind, targetId)
                + keys.revokeRestrictedTo(kind, targetId);
    }
}
