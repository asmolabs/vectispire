package com.asmolabs.zanshin.core.api.scim.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

/**
 * SCIM 2.0 Error Response (RFC 7644).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScimErrorResponse(
        List<String> schemas,
        String status,
        String scimType,
        String detail) {

    public static final String SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";

    public static ScimErrorResponse of(int status, String detail) {
        return new ScimErrorResponse(List.of(SCHEMA_ERROR), String.valueOf(status), null, detail);
    }
}
