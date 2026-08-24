package com.asmolabs.zanshin.common.domain.apis;

import java.util.List;

/**
 * An API contract (OpenAPI 3, Swagger 2, GraphQL schema, Proto) discovered in the repository.
 */
public record ApiContract(
        String contractPath,
        String format,
        String title,
        String version,
        int endpointsCount,
        List<String> declaredPaths) {

    public ApiContract {
        if (declaredPaths == null) {
            declaredPaths = List.of();
        }
    }
}
