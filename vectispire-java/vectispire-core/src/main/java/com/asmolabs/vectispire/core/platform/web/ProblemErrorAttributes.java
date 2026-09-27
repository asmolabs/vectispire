package com.asmolabs.vectispire.core.platform.web;

import java.util.LinkedHashMap;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.webmvc.error.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

/**
 * What the container's error page answers, in the members of an RFC 9457 problem.
 *
 * <p><b>What still reaches it.</b> {@code ApiExceptionHandler} answers everything a controller
 * throws, and the filter chain writes its own refusals; what is left is an exception thrown by a
 * filter, and a status set by the container itself. Those went to Spring Boot's error page, whose
 * body is {@code {timestamp, status, error, path}} — no {@code detail}, so the one failure that most
 * needs explaining was the one the interface could not read a sentence from.
 *
 * <p><b>The members, not the media type.</b> Boot's error controller negotiates the content type
 * from {@code Accept}, so this answers {@code application/json} to a client that accepts anything
 * and {@code application/problem+json} to one that asks for it. Replacing the controller to force
 * the second would add a route to {@code /error} that the security chain opens only to the error
 * dispatch, and that the route-authorization rules would have to be taught about; the members are
 * what a client reads, and they are the same.
 *
 * <p>A 5xx is answered with a reference and logged under it, never with the exception's message:
 * nothing that reaches this point was written for a client.
 */
@Component
public class ProblemErrorAttributes extends DefaultErrorAttributes {

    @Override
    public Map<String, @Nullable Object> getErrorAttributes(WebRequest request, ErrorAttributeOptions options) {
        Map<String, @Nullable Object> defaults = super.getErrorAttributes(request, ErrorAttributeOptions.defaults());
        int code = defaults.get("status") instanceof Integer status ? status : 500;
        HttpStatus status = HttpStatus.resolve(code);
        Object path = defaults.get("path");

        Map<String, @Nullable Object> problem = new LinkedHashMap<>();
        problem.put("title", status == null ? "Error" : status.getReasonPhrase());
        problem.put("status", code);
        if (code >= 500) {
            Throwable error = getError(request);
            String reference = UnexpectedFailure.record(
                    request instanceof ServletWebRequest servlet ? servlet.getRequest().getMethod() : "?",
                    String.valueOf(path),
                    error == null ? new IllegalStateException("status " + code + " set without an exception") : error);
            problem.put("detail", UnexpectedFailure.detail(reference));
            problem.put(UnexpectedFailure.REFERENCE, reference);
        } else {
            problem.put("detail", status == null ? "The request was refused." : status.getReasonPhrase() + ".");
        }
        problem.put("instance", path);
        return problem;
    }
}
