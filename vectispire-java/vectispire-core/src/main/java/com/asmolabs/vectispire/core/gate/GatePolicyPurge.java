package com.asmolabs.vectispire.core.gate;

import com.asmolabs.vectispire.common.domain.targets.TargetDeleted;
import com.asmolabs.vectispire.common.domain.targets.TargetPurge;
import com.asmolabs.vectispire.core.repositories.GatePolicies;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A deleted target's stored gate policies go with it.
 *
 * <p>They name the target by kind and identifier, with no foreign key to cascade through. The
 * verdicts the gate recorded are left to the schema's cascade from the target, as they always were.
 * Synchronous and in the deleting transaction, like every {@link TargetPurge} listener.
 */
@Component
class GatePolicyPurge {

    private final GatePolicies policies;

    GatePolicyPurge(GatePolicies policies) {
        this.policies = policies;
    }

    @EventListener
    @Order(TargetPurge.Phase.REFERENCES)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(TargetDeleted deleted) {
        policies.deleteByTarget(deleted.kind(), deleted.id());
    }
}
