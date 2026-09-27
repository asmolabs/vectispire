package com.asmolabs.vectispire.core.platform.web;

import com.asmolabs.vectispire.common.domain.apikeys.InvalidApiKeyException;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.issues.InvalidTriageException;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import com.asmolabs.vectispire.common.domain.rules.InvalidRuleSetException;
import com.asmolabs.vectispire.common.domain.scheduling.InvalidCronExpressionException;
import com.asmolabs.vectispire.core.access.web.security.ApiKeyRateLimitedException;
import com.asmolabs.vectispire.core.access.web.security.CredentialNotAcceptedException;
import com.asmolabs.vectispire.core.access.web.security.PasswordChangeRequiredException;
import com.asmolabs.vectispire.core.access.web.security.RequestBodyTooLargeException;
import com.asmolabs.vectispire.core.crypto.MissingEncryptionKeyException;
import com.asmolabs.vectispire.core.exports.AttestationService;
import com.asmolabs.vectispire.core.plugins.PluginConflictException;
import com.asmolabs.vectispire.core.plugins.SarifImportRefusedException;
import com.asmolabs.vectispire.core.plugins.SarifTooLargeException;
import com.asmolabs.vectispire.core.scanning.CredentialWithheldException;
import com.asmolabs.vectispire.core.scanning.ScanTriggerService;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * How a refusal becomes an HTTP answer: an RFC 9457 problem, always with a {@code detail}.
 *
 * <p><b>The mapping is here and nowhere else.</b> Scattering it across the controllers is how
 * the same refusal comes to answer 400 on one route and 500 on another — and a 500 is what an
 * operator reports as a bug in Vectispire rather than as a mistake in their own request.
 *
 * <p><b>One shape for every error, the framework's included.</b> Only the exceptions listed below
 * used to answer a problem. A {@code ResponseStatusException} — thirty-seven of them, each with a
 * sentence written for the caller — and every refusal Spring MVC makes on its own (an unknown route,
 * a wrong method or media type, a body that is not JSON) went to the container's error page instead:
 * {@code {timestamp, status, error, path}}, no {@code detail}, so the interface's {@code messageOf}
 * found nothing to show and fell back to its generic sentence. Extending {@link
 * ResponseEntityExceptionHandler} makes Spring's own refusals problems; a {@code
 * ResponseStatusException} is one of them, and its reason becomes the {@code detail}.
 *
 * <p>Every message below is meant to be shown as it stands. These exceptions carry text written
 * for the person who triggered them; replacing it with a generic sentence would throw away the
 * only part that helps.
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    /**
     * A malformed request: the caller can fix it and try again.
     *
     * <p><b>{@link InvalidInputException}, not {@link IllegalArgumentException}.</b> The second was
     * mapped here, so every one answered 400 with its message — the sentences written for an
     * operator, and alongside them Spring Data's "The given id must not be null", a JDK parser's
     * "For input string", a crypto library's complaint about a key: internals on the wire, and a
     * programming error reported as the caller's fault. A deliberate refusal now says so by its type;
     * anything else is {@link #unexpected}.
     */
    @ExceptionHandler({
        InvalidTriageException.class,
        InvalidRuleSetException.class,
        InvalidApiKeyException.class,
        InvalidCronExpressionException.class,
        InvalidInputException.class
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
    @ExceptionHandler({MissingEncryptionKeyException.class, CredentialWithheldException.class})
    ProblemDetail preconditionFailed(RuntimeException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.PRECONDITION_FAILED, error.getMessage());
    }

    /**
     * A SARIF upload refused for who sent it or what it claims — a session, an undeclared key, an
     * undeclared tool. 403: the route exists for a declared source, and saying so names no repository.
     */
    @ExceptionHandler(SarifImportRefusedException.class)
    ProblemDetail sarifImportRefused(SarifImportRefusedException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, error.getMessage());
    }

    /** A key or an agent credential on a route that did not invite it (decision 0024). */
    @ExceptionHandler(CredentialNotAcceptedException.class)
    ProblemDetail credentialNotAccepted(CredentialNotAcceptedException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, error.getMessage());
    }

    @ExceptionHandler(ApiKeyRateLimitedException.class)
    ResponseEntity<ProblemDetail> apiKeyRateLimited(ApiKeyRateLimitedException error) {
        long seconds = Math.max(1, error.retryAfter().toSeconds());
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, error.getMessage());
        problem.setProperty("retryAfterSeconds", seconds);
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(seconds))
                .body(problem);
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
        SolutionAdministrationService.SolutionNotEmptyException.class,
        PluginConflictException.class
    })
    ProblemDetail conflict(RuntimeException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, error.getMessage());
    }

    /**
     * A body past its route's ceiling, found while it was being read — by {@code access}'s
     * {@code RequestBodyLimitFilter}. A declared length over the ceiling is refused by the filter
     * itself, before this point.
     */
    @ExceptionHandler({RequestBodyTooLargeException.class, SarifTooLargeException.class})
    ProblemDetail contentTooLarge(RuntimeException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONTENT_TOO_LARGE, error.getMessage());
    }

    /**
     * A row that is not there, or not the caller's — in the one sentence both get.
     *
     * <p>{@link NotFoundException} and not {@link java.util.NoSuchElementException}, which {@code
     * Optional.orElseThrow()} throws: a lookup that cannot fail — the row a service has just saved —
     * answered 404 "No value present" when it did, and the defect read as the absence of what the
     * caller had asked for.
     */
    @ExceptionHandler(NotFoundException.class)
    ProblemDetail notFound(NotFoundException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, error.getMessage());
    }

    /**
     * Whatever nobody mapped: a 500 that quotes a reference, and the failure in the log under it.
     *
     * <p><b>Spring Security's own are handed back.</b> A {@code @PreAuthorize} refusal is thrown from
     * the handler; answered here it would be a 500, and it would never reach the chain's denied
     * handler, which is what audits it. Rethrowing the exception the resolver was given makes it
     * pass this resolver silently, as if nothing had matched.
     */
    @ExceptionHandler(Exception.class)
    ResponseEntity<ProblemDetail> unexpected(Exception error, HttpServletRequest request) throws Exception {
        if (error instanceof AccessDeniedException || error instanceof AuthenticationException) {
            throw error;
        }
        String reference = UnexpectedFailure.record(request.getMethod(), request.getRequestURI(), error);
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR, UnexpectedFailure.detail(reference));
        problem.setProperty(UnexpectedFailure.REFERENCE, reference);
        return ResponseEntity.internalServerError().body(problem);
    }

    /**
     * An unmapped path, in Vectispire's words.
     *
     * <p>Spring's own detail is "No static resource api/v1/…": the dispatcher looked for a file after
     * no controller matched, and says so. True of the implementation, and misleading to a client of
     * an API, which asked for a route.
     */
    @Override
    protected @Nullable ResponseEntity<Object> handleNoResourceFoundException(
            NoResourceFoundException error, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, "Nothing is served at this path.");
        return handleExceptionInternal(error, problem, headers, status, request);
    }

    /**
     * A body that is not the JSON this route reads — or that is, and a value in it was refused.
     *
     * <p><b>The second case keeps its sentence.</b> A record that refuses a value in its constructor
     * is reached through Jackson, which wraps the refusal; Spring then reports the wrapper, and its
     * detail is "Failed to read request". Before this handler extended {@link
     * ResponseEntityExceptionHandler}, the {@code IllegalArgumentException} mapping caught the
     * wrapped cause and its message reached the client; this keeps it doing so for a refusal
     * written as one, and for nothing else — Jackson's own messages quote the parser's position and
     * the Java type it was building.
     */
    @Override
    protected @Nullable ResponseEntity<Object> handleHttpMessageNotReadable(
            org.springframework.http.converter.HttpMessageNotReadableException error,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        String detail = "The request body could not be read: it is not JSON, or not the shape this route expects.";
        for (Throwable cause = error.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof InvalidInputException refused && refused.getMessage() != null) {
                detail = refused.getMessage();
                break;
            }
        }
        return handleExceptionInternal(error, ProblemDetail.forStatusAndDetail(status, detail), headers, status, request);
    }

    /**
     * Every problem this class answers carries a {@code detail}.
     *
     * <p>A {@code ResponseStatusException} built without a reason, or a framework refusal whose
     * message source has nothing for it, would otherwise answer a problem with no sentence at all —
     * which the interface renders as its generic fallback, the defect this class exists to end. The
     * status's own phrase is a poor sentence and still a better one than nothing.
     */
    @Override
    protected ResponseEntity<Object> createResponseEntity(
            @Nullable Object body, HttpHeaders headers, HttpStatusCode statusCode, WebRequest request) {
        if (body instanceof ProblemDetail problem && (problem.getDetail() == null || problem.getDetail().isBlank())) {
            HttpStatus known = HttpStatus.resolve(statusCode.value());
            problem.setDetail(known == null ? "The request was refused." : known.getReasonPhrase() + ".");
        }
        return super.createResponseEntity(body, headers, statusCode, request);
    }
}
