package com.asmolabs.vectispire.core.access.web.scim.dto;

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

    /**
     * A page of the list: {@code itemsPerPage} the resources it holds, {@code totalResults} every resource the
     * request matched — the figure a client pages against (RFC 7644 §3.4.2).
     */
    public static <T> ScimListResponse<T> page(List<T> resources, int totalResults, int startIndex) {
        return new ScimListResponse<>(List.of(SCHEMA_LIST), totalResults, startIndex, resources.size(), resources);
    }
}
