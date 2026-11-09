package com.asmolabs.vectispire.core.access.web.scim;

import com.asmolabs.vectispire.core.access.web.scim.dto.ScimErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * A SCIM route's refusal, answered in SCIM's error schema (RFC 7644 §3.12).
 *
 * <p><b>The absent resource and the taken name were bodiless.</b> A 404 and a 409 with nothing in them
 * gave a directory no {@code detail} to log and no {@code scimType} to act on — RFC 7644 §3.3 names
 * {@code uniqueness} for the second, which is how a directory tells "already provisioned, link it" from
 * a failure. Thrown by the routes and answered by their own handlers, so the routes keep the success
 * body as their declared type.
 */
final class ScimRefusal extends RuntimeException {

    private final HttpStatus status;
    private final String scimType;

    private ScimRefusal(HttpStatus status, String scimType, String detail) {
        super(detail);
        this.status = status;
        this.scimType = scimType;
    }

    static ScimRefusal notFound(String detail) {
        return new ScimRefusal(HttpStatus.NOT_FOUND, null, detail);
    }

    /** RFC 7644 §3.3: a resource whose unique attribute another one holds. */
    static ScimRefusal uniqueness(String detail) {
        return new ScimRefusal(HttpStatus.CONFLICT, ScimErrorResponse.UNIQUENESS, detail);
    }

    ResponseEntity<ScimErrorResponse> response() {
        return ResponseEntity.status(status).body(ScimErrorResponse.of(status.value(), scimType, getMessage()));
    }
}
