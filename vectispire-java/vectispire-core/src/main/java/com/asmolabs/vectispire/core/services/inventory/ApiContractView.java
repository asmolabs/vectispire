package com.asmolabs.vectispire.core.services.inventory;

import com.asmolabs.vectispire.core.persistence.ApiContractEntity;
import java.time.Instant;

/**
 * A declared API contract as a route returns it: the row's fields, not the row — no JPA entity
 * crosses the API. Names are the entity's properties, so the wire is unchanged.
 */
public record ApiContractView(
        Long id,
        Long repositoryId,
        Long scanId,
        String contractPath,
        String format,
        String title,
        String version,
        Integer endpointsCount,
        Instant createdAt) {

    public static ApiContractView of(ApiContractEntity row) {
        return new ApiContractView(
                row.getId(),
                row.getRepositoryId(),
                row.getScanId(),
                row.getContractPath(),
                row.getFormat(),
                row.getTitle(),
                row.getVersion(),
                row.getEndpointsCount(),
                row.getCreatedAt());
    }
}
