package com.asmolabs.zanshin.core.api.scim.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * SCIM 2.0 Patch Operation schema (RFC 7644 Section 3.5.2).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScimPatchOp(
        List<String> schemas,
        @com.fasterxml.jackson.annotation.JsonProperty("Operations") List<PatchOperation> operations) {

    public static final String SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PatchOperation(
            String op,
            String path,
            JsonNode value) {}
}
