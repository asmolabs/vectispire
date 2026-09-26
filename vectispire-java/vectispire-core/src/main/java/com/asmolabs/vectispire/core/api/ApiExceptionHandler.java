package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.apikeys.InvalidApiKeyException;
import com.asmolabs.vectispire.common.domain.issues.InvalidTriageException;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import com.asmolabs.vectispire.common.domain.rules.InvalidRuleSetException;
import com.asmolabs.vectispire.common.domain.scheduling.InvalidCronExpressionException;
import com.asmolabs.vectispire.core.access.web.security.PasswordChangeRequiredException;
import com.asmolabs.vectispire.core.access.web.security.RequestBodyTooLargeException;
import com.asmolabs.vectispire.core.crypto.MissingEncryptionKeyException;
import com.asmolabs.vectispire.core.exports.AttestationService;
import com.asmolabs.vectispire.core.scanning.InsecureCredentialTransportException;
import com.asmolabs.vectispire.core.scanning.ScanTriggerService;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService;
import java.util.NoSuchElementException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * How a domain refusal becomes an HTTP status.
 *
 * <p><b>The mapping is here and nowhere else.</b> Scattering it across the controllers is how
 * the same refusal comes to answer 400 on one route and 500 on another — and a 500 is what an
 * operator reports as a bug in Vectispire rather than as a mistake in their own request.
 *
 * <p>Every message below is meant to be shown as it stands. These exceptions carry text written
 * for the person who triggered them; replacing it with a generic sentence would throw away the
 * only part that helps.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    /** A malformed request: the caller can fix it and try again. */
    @ExceptionHandler({
        InvalidTriageException.class,
        InvalidRuleSetException.class,
        InvalidApiKeyException.class,
        InvalidCronExpressionException.class,
        IllegalArgumentException.class
    })
    ProblemDetail badRequest(RuntimeException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, error.getMessage());
    }

    /**
     * A destination the URL guard refused.
     *
     * <p>422 rather than 400: the request is well formed and the value is the operator's own
     * setting. "Unprocessable" says the server understood and will not, which is exactly the
     * case.
     */
    @ExceptionHandler(UnsafeUrlException.class)
    ProblemDetail unsafeUrl(UnsafeUrlException error) {
        // 422 by number: Spring deprecated the constant in favour of the WebDAV spelling
        // `UNPROCESSABLE_CONTENT`, which is the same code under a name nobody uses in an API
        // contract. The number is what the frontend matches on, and it is not moving.
        return ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(422), error.getMessage());
    }

    /**
     * The deployment is misconfigured, not broken.
     *
     * <p>412 for both: an operator reading "precondition failed" with the message attached goes
     * and sets an environment variable. The same case as a 500 sends them to a stack trace and
     * then to an issue tracker.
     */
    @ExceptionHandler({MissingEncryptionKeyException.class, InsecureCredentialTransportException.class})
    ProblemDetail preconditionFailed(RuntimeException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.PRECONDITION_FAILED, error.getMessage());
    }

    /** A key or an agent credential on a route that did not invite it (decision 0024). */
    @ExceptionHandler(com.asmolabs.vectispire.core.access.web.security.CredentialNotAcceptedException.class)
    ProblemDetail credentialNotAccepted(com.asmolabs.vectispire.core.access.web.security.CredentialNotAcceptedException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, error.getMessage());
    }

    @ExceptionHandler(com.asmolabs.vectispire.core.access.web.security.ApiKeyRateLimitedException.class)
    org.springframework.http.ResponseEntity<ProblemDetail> apiKeyRateLimited(
            com.asmolabs.vectispire.core.access.web.security.ApiKeyRateLimitedException error) {
        return org.springframework.http.ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(Math.max(1, error.retryAfter().toSeconds())))
                .body(ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, error.getMessage()));
    }

    /**
     * The caller is authenticated and owes a password change.
     *
     * <p>403 and not 401: the token is good and the server knows who this is. 401 would send the
     * client back to sign in, which it has already done — and would do again, in a loop.
     */
    @ExceptionHandler(PasswordChangeRequiredException.class)
    ProblemDetail passwordChangeRequired(PasswordChangeRequiredException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, error.getMessage());
    }

    /**
     * The request conflicts with the state the server is already in.
     *
     * <p>409 rather than 400: nothing about the request is malformed, and a caller that retries
     * it unchanged in five minutes may well succeed. "Already queued" is the state's answer, not
     * the request's fault. So is "not attestable": a scan still running may complete, and the
     * refusal names what is missing rather than serving a statement with it invented. And so is
     * "this solution still holds projects": deleting them first makes the same request succeed.
     */
    @ExceptionHandler({
        ScanTriggerService.AlreadyQueuedException.class,
        AttestationService.NotAttestableException.class,
        SolutionAdministrationService.SolutionNotEmptyException.class
    })
    ProblemDetail conflict(RuntimeException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, error.getMessage());
    }

    /**
     * A body past its route's ceiling, found while it was being read — by {@code access}'s
     * {@code RequestBodyLimitFilter}. A declared length over the ceiling is refused by the filter
     * itself, before this point.
     */
    @ExceptionHandler(RequestBodyTooLargeException.class)
    ProblemDetail contentTooLarge(RuntimeException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONTENT_TOO_LARGE, error.getMessage());
    }

    /** A row that is not there. Thrown by the {@code orElseThrow} of a lookup. */
    @ExceptionHandler(NoSuchElementException.class)
    ProblemDetail notFound(NoSuchElementException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, error.getMessage());
    }
}
