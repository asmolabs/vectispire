package com.asmolabs.zanshin.core.api.scim.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * SCIM 2.0 User Resource schema (RFC 7643).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScimUserDto(
        List<String> schemas,
        String id,
        String externalId,
        String userName,
        Name name,
        String displayName,
        List<Email> emails,
        List<RoleEntry> roles,
        Boolean active,
        Meta meta) {

    public static final String SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User";

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Name(String formatted, String familyName, String givenName) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Email(String value, String type, Boolean primary) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record RoleEntry(String value, Boolean primary) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Meta(
            @JsonProperty("resourceType") String resourceType,
            String created,
            String lastModified,
            String location) {}
}
