package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageRepository;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyTarget;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.OrphanedTargetRows;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.TargetDeleted;
import com.asmolabs.vectispire.core.targets.TargetPurge;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A deleted target's weekly OWASP record goes with it.
 *
 * <p>The rows name the target by kind and identifier, with no foreign key (V67, written once), so
 * nothing cascades into them; they go in the first phase, with the other rows of that shape.
 * Synchronous and in the deleting transaction, like every {@link TargetPurge} listener. Without it a
 * deleted target would go on appearing in the past weeks of the whole estate's heatmap — and under an
 * identifier an engine may hand out again, in somebody else's.
 *
 * <p><b>The orphan sweep too, unlike the gate policies.</b> A capture reads the estate before it
 * writes, so a target deleted in between is written after its purge ran — and the next capture only
 * rewrites the current week. The sweep asks the targets' owner which of the targets the record names
 * still exist, in batches ({@code TargetCatalog}), and drops the rest.
 */
@Component
class OwaspCoveragePurge {

    private static final Logger log = LoggerFactory.getLogger(OwaspCoveragePurge.class);

    private final OwaspWeeklyCoverageRepository weeks;
    private final TargetCatalog targets;

    OwaspCoveragePurge(OwaspWeeklyCoverageRepository weeks, TargetCatalog targets) {
        this.weeks = weeks;
        this.targets = targets;
    }

    @EventListener
    @Order(TargetPurge.Phase.REFERENCES)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(TargetDeleted deleted) {
        weeks.deleteByTarget(deleted.kind(), deleted.id());
    }

    @EventListener
    @Order(TargetPurge.Phase.REFERENCES)
    @Transactional(propagation = Propagation.MANDATORY)
    public void sweep(OrphanedTargetRows sweep) {
        List<OwaspWeeklyTarget> named = weeks.targets();
        Set<Long> repositories = targets.repositories(idsOf(named, TeamRules.KIND_REPOSITORY)).stream()
                .map(RepositoryView::id)
                .collect(Collectors.toSet());
        Set<Long> containers = targets.containers(idsOf(named, TeamRules.KIND_CONTAINER)).stream()
                .map(ContainerView::id)
                .collect(Collectors.toSet());

        int deleted = 0;
        for (OwaspWeeklyTarget target : named) {
            boolean exists = switch (target.kind()) {
                case TeamRules.KIND_REPOSITORY -> repositories.contains(target.id());
                case TeamRules.KIND_CONTAINER -> containers.contains(target.id());
                // A kind this build does not write is nobody's to judge; left as it is.
                default -> true;
            };
            if (!exists) {
                deleted += weeks.deleteByTarget(target.kind(), target.id());
            }
        }
        if (deleted > 0) {
            log.info("Cleaned up {} weekly OWASP coverage rows of deleted targets.", deleted);
        }
    }

    private static List<Long> idsOf(List<OwaspWeeklyTarget> named, String kind) {
        return named.stream().filter(target -> target.kind().equals(kind)).map(OwaspWeeklyTarget::id).toList();
    }
}
