package com.asmolabs.vectispire.core.api.scim.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * SCIM 2.0 ListResponse schema (RFC 7643 / RFC 7644).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScimListResponse<T>(
        List<String> schemas,
        int totalResults,
        int startIndex,
        int itemsPerPage,
        @JsonProperty("Resources") List<T> resources) {

    public static final String SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

    public static <T> ScimListResponse<T> of(List<T> resources) {
        return new ScimListResponse<>(
                List.of(SCHEMA_LIST),
                resources.size(),
                1,
                resources.size(),
                resources);
    }
}
