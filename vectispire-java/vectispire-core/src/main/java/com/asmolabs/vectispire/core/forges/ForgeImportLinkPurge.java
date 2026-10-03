package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.targets.TargetDeleted;
import com.asmolabs.vectispire.core.targets.TargetPurge;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A deleted target's provenance link goes with it (decision 0037 §5).
 *
 * <p>The link names the target by its id with no foreign key — {@code t_repository} is another module's table — so
 * nothing cascades into it; it goes in the first phase, with the other rows of that shape. Synchronous and in the
 * deleting transaction, like every {@link TargetPurge} listener. Left behind, it would mark the repository <em>already
 * imported</em> on the selection screen, as a target that no longer exists, and the next import would skip it.
 *
 * <p>No orphan sweep: a link is written in the transaction that creates its target, so no deletion can come between
 * the two.
 */
@Component
class ForgeImportLinkPurge {

    private final ForgeImportLinkRepository links;

    ForgeImportLinkPurge(ForgeImportLinkRepository links) {
        this.links = links;
    }

    @EventListener
    @Order(TargetPurge.Phase.REFERENCES)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(TargetDeleted deleted) {
        if (deleted.target() instanceof ScanTarget.Repository repository) {
            links.deleteByRepository(repository.id());
        }
    }
}
