package com.asmolabs.vectispire.core.access.web.scim.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import tools.jackson.databind.JsonNode;

/**
 * SCIM 2.0 Patch Operation schema (RFC 7644 Section 3.5.2).
 *
 * <p>{@code value} is a Jackson 3 node because the request body is read by Jackson 3 — see
 * {@link com.asmolabs.vectispire.core.access.ScimProvisioningService.PatchOperation}.
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
