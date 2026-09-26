package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import java.time.Instant;

/**
 * A watched container image as the layers above the services hold it: the row's properties under
 * their own names, not the row.
 */
public record ContainerView(
        Long id,
        String registry,
        String imageName,
        String tag,
        Integer scanIntervalMinutes,
        String scanCron,
        String requiredAgentLabel,
        Instant lastScheduledScanAt,
        String tier,
        boolean inCertifiedScope) {

    public static ContainerView of(ContainerEntity container) {
        return new ContainerView(
                container.getId(),
                container.getRegistry(),
                container.getImageName(),
                container.getTag(),
                container.getScanIntervalMinutes(),
                container.getScanCron(),
                container.getRequiredAgentLabel(),
                container.getLastScheduledScanAt(),
                container.getTier(),
                container.isInCertifiedScope());
    }
}
