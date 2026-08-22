package com.asmolabs.zanshin.core.api.scim.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * SCIM 2.0 Group Resource schema (RFC 7643).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScimGroupDto(
        List<String> schemas,
        String id,
        String externalId,
        String displayName,
        List<Member> members,
        Meta meta) {

    public static final String SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Member(String value, String display, String ref) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Meta(
            @JsonProperty("resourceType") String resourceType,
            String created,
            String lastModified,
            String location) {}
}
