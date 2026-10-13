package com.asmolabs.vectispire.core.access.web.scim.dto;

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

    /** RFC 7644 §3.12: the filter syntax was invalid, or the filter is not supported. */
    public static final String INVALID_FILTER = "invalidFilter";

    public static ScimErrorResponse of(int status, String detail) {
        return of(status, null, detail);
    }

    public static ScimErrorResponse of(int status, String scimType, String detail) {
        return new ScimErrorResponse(List.of(SCHEMA_ERROR), String.valueOf(status), scimType, detail);
    }
}
