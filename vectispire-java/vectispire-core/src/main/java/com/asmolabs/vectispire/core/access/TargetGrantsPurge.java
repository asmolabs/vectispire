package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.targets.TargetDeleted;
import com.asmolabs.vectispire.common.domain.targets.TargetPurge;
import com.asmolabs.vectispire.core.access.persistence.TeamTargets;
import com.asmolabs.vectispire.core.access.persistence.UserTargets;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A deleted target's grants, to accounts and to teams, go with it.
 *
 * <p>Not tidiness: {@code (target_kind, target_id)} cascades from nothing, and a stale grant would
 * come to name whichever target later took the identifier — see {@link UserTargets#deleteByTarget}.
 * Synchronous and in the deleting transaction, like every {@link TargetPurge} listener.
 */
@Component
class TargetGrantsPurge {

    private final UserTargets userTargets;
    private final TeamTargets teamTargets;

    TargetGrantsPurge(UserTargets userTargets, TeamTargets teamTargets) {
        this.userTargets = userTargets;
        this.teamTargets = teamTargets;
    }

    @EventListener
    @Order(TargetPurge.Phase.REFERENCES)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(TargetDeleted deleted) {
        userTargets.deleteByTarget(deleted.kind(), deleted.id());
        teamTargets.deleteByTarget(deleted.kind(), deleted.id());
    }
}
