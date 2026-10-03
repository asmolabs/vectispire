package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomComponentRepository;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomRepository;
import com.asmolabs.vectispire.core.targets.TargetDeleted;
import com.asmolabs.vectispire.core.targets.TargetPurge;
import java.util.List;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A repository's build SBOMs and their components, in the transaction that deletes it.
 *
 * <p>No foreign key follows a repository into these tables (V82, a common migration), so without this
 * an SBOM would outlive its repository and complete the scans of whatever later took its identifier.
 * Nothing references them, so they go in the first phase with the other rows naming a target by
 * identifier alone; the components first, found through their imports. The scans' completed rows go
 * with the scans ({@code ComponentPurge}).
 */
@Component
class BuildSbomPurge {

    private static final int BATCH = 1_000;

    private final BuildSbomRepository imports;
    private final BuildSbomComponentRepository listed;

    BuildSbomPurge(BuildSbomRepository imports, BuildSbomComponentRepository listed) {
        this.imports = imports;
        this.listed = listed;
    }

    @EventListener
    @Order(TargetPurge.Phase.REFERENCES)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(TargetDeleted deleted) {
        if (deleted.target() instanceof ScanTarget.Repository repository) {
            List<Long> ids = imports.idsOfRepository(repository.id());
            for (int from = 0; from < ids.size(); from += BATCH) {
                List<Long> batch = ids.subList(from, Math.min(ids.size(), from + BATCH));
                listed.deleteByImportIds(batch);
                imports.deleteByIds(batch);
            }
        }
    }
}
