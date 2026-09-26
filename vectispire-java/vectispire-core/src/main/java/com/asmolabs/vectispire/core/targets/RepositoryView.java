package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.UUID;

/**
 * A monitored repository as the layers above the services hold it: the row's properties under
 * their own names, not the row.
 *
 * <p>{@code badgeToken} is left out: it is the capability an anonymous badge is served under, and
 * nothing that reads a repository through this record has a use for it.
 */
public record RepositoryView(
        Long id,
        String url,
        String branch,
        String subPath,
        String name,
        Integer scanIntervalMinutes,
        String scanCron,
        String requiredAgentLabel,
        Instant lastScheduledScanAt,
        UUID sshKeyId,
        UUID httpsTokenId,
        String tier,
        boolean inCertifiedScope,
        Long projectId) {

    public static RepositoryView of(RepositoryEntity repository) {
        return new RepositoryView(
                repository.getId(),
                repository.getUrl(),
                repository.getBranch(),
                repository.getSubPath(),
                repository.getName(),
                repository.getScanIntervalMinutes(),
                repository.getScanCron(),
                repository.getRequiredAgentLabel(),
                repository.getLastScheduledScanAt(),
                repository.getSshKeyId(),
                repository.getHttpsTokenId(),
                repository.getTier(),
                repository.isInCertifiedScope(),
                repository.getProjectId());
    }
}
