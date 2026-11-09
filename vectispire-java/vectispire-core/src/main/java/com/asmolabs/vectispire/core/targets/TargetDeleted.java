package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import java.util.Objects;

/**
 * A repository or a container image is being deleted, in the transaction that deletes it.
 *
 * <p>Every row naming it goes with it; see {@link TargetPurge} for why each domain purges its own,
 * synchronously, and in which order.
 */
public record TargetDeleted(ScanTarget target) implements TargetPurge {

    public TargetDeleted {
        Objects.requireNonNull(target, "target");
    }

    /** The kind as grants and gate policies store it next to the identifier. */
    public String kind() {
        return switch (target) {
            case ScanTarget.Repository ignored -> TeamRules.KIND_REPOSITORY;
            case ScanTarget.Container ignored -> TeamRules.KIND_CONTAINER;
        };
    }

    public long id() {
        return switch (target) {
            case ScanTarget.Repository repository -> repository.id();
            case ScanTarget.Container container -> container.id();
        };
    }
}
