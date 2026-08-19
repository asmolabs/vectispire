package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.apikeys.InvalidApiKeyException;
import com.asmolabs.zanshin.common.domain.issues.InvalidTriageException;
import com.asmolabs.zanshin.common.domain.net.UnsafeUrlException;
import com.asmolabs.zanshin.common.domain.rules.InvalidRuleSetException;
import com.asmolabs.zanshin.common.domain.scheduling.InvalidCronExpressionException;
import com.asmolabs.zanshin.core.api.security.PasswordChangeRequiredException;
import com.asmolabs.zanshin.core.services.InsecureCredentialTransportException;
import com.asmolabs.zanshin.core.services.MissingEncryptionKeyException;
import com.asmolabs.zanshin.core.services.ScanTriggerService;
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
 * operator reports as a bug in Zanshin rather than as a mistake in their own request.
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
     * the request's fault.
     */
    @ExceptionHandler(ScanTriggerService.AlreadyQueuedException.class)
    ProblemDetail conflict(RuntimeException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, error.getMessage());
    }

    /** A row that is not there. Thrown by the {@code orElseThrow} of a lookup. */
    @ExceptionHandler(NoSuchElementException.class)
    ProblemDetail notFound(NoSuchElementException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, error.getMessage());
    }
}
