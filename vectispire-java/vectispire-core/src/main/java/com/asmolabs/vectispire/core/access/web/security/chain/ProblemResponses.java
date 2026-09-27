package com.asmolabs.vectispire.core.access.web.security.chain;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/**
 * The refusals the filter chain answers before a controller is reached, in the shape the
 * controllers' refusals take: RFC 9457, with a {@code detail}.
 *
 * <p><b>Why the chain writes its own.</b> A filter runs outside Spring MVC, so {@code
 * ApiExceptionHandler} never sees what it refuses. The chain's refusals were each written by hand
 * and disagreed: the three limiters answered {@code {"message": …}} as {@code application/json}, the
 * body limit a problem, the 401 nothing at all, and the 403 went through the container's error page
 * and came back as {@code {timestamp, status, error, path}}. A client reading {@code detail} — the
 * interface does — had four shapes to guess between for one kind of answer.
 *
 * <p><b>Serialised, never formatted.</b> The body limit built its problem with {@code
 * String.formatted}; a detail with a quote in it would have produced a document no client could
 * parse. And UTF-8 rather than the servlet's ISO-8859-1 default, which is what the writer used.
 */
final class ProblemResponses {

    private static final ObjectMapper JSON = new ObjectMapper();

    private ProblemResponses() {}

    static void write(HttpServletRequest request, HttpServletResponse response, HttpStatus status, String detail)
            throws IOException {
        write(request, response, status, detail, Map.of());
    }

    /** @param properties RFC 9457's extension members — {@code retryAfterSeconds} for a 429 */
    static void write(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpStatus status,
            String detail,
            Map<String, Object> properties) throws IOException {
        Map<String, Object> problem = new LinkedHashMap<>();
        problem.put("title", status.getReasonPhrase());
        problem.put("status", status.value());
        problem.put("detail", detail);
        problem.put("instance", request.getRequestURI());
        problem.putAll(properties);

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8);
        response.getWriter().write(JSON.writeValueAsString(problem));
    }
}
