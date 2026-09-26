package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.core.access.persistence.TeamTargets;
import com.asmolabs.vectispire.core.access.persistence.UserTargets;
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
 * {@link UserTargets#deleteByTarget}). The deleting module used to write both grant tables itself
 * (a step-5 finding of decision 0028); it now asks here.
 */
@Service
public class TargetGrants {

    private final UserTargets userTargets;
    private final TeamTargets teamTargets;

    public TargetGrants(UserTargets userTargets, TeamTargets teamTargets) {
        this.userTargets = userTargets;
        this.teamTargets = teamTargets;
    }

    /**
     * Revokes every grant naming the target and says how many went.
     *
     * <p>{@code MANDATORY}: the revocation belongs to the deletion that causes it. Committed on its
     * own, a deletion that then rolled back would leave its target standing and its grants gone.
     *
     * @param kind as the grant tables store it — {@code TeamRules.KIND_REPOSITORY}, {@code
     *     KIND_CONTAINER} or {@code KIND_PROJECT}
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public int revokeAll(String kind, long targetId) {
        return userTargets.deleteByTarget(kind, targetId) + teamTargets.deleteByTarget(kind, targetId);
    }
}
