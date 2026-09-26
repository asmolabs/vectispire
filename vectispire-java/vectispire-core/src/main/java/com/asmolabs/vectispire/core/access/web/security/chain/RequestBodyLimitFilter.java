package com.asmolabs.vectispire.core.access.web.security.chain;

import com.asmolabs.vectispire.core.access.web.security.RequestBodyTooLargeException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A ceiling on the three request bodies read whole into memory before anything looks at them.
 *
 * <p><b>Why a filter, and not a container setting.</b> Tomcat's {@code maxPostSize} and Spring's
 * multipart limits apply to form and multipart bodies only; a {@code @RequestBody String} or
 * {@code byte[]} is read by a message converter to the end of the stream, whatever its length. So
 * the anonymous tracker webhook, the VEX import and an agent's result had no ceiling at all — a
 * client could make the process buffer as much as it cared to send. Nothing else in the stack bounds
 * them, and only a filter sees the body before the converter does.
 *
 * <p><b>Two checks.</b> A declared {@code Content-Length} over the ceiling is answered 413 at once,
 * without reading a byte. A body with no declared length — chunked — is counted as the converter
 * reads it, and refused the moment it passes the ceiling; {@link RequestBodyTooLargeException} is
 * unchecked on purpose, because the converters catch {@code IOException} and would turn it into a
 * 400 that says the JSON was malformed.
 *
 * <p><b>The limits, and why each.</b>
 * <ul>
 *   <li>Webhook, 1 MB: a Jira or GitLab issue event with its changelog is tens of kilobytes; ten
 *       times the largest seen leaves room and still stops an anonymous client early.
 *   <li>VEX import, 16 MB: an OpenVEX or CycloneDX VEX document for a large product runs to a few
 *       megabytes; it is uploaded by a signed-in account, and parsed whole.
 *   <li>Agent result, 256 MB: the result carries the SBOM, and a large container image's is tens of
 *       megabytes of JSON. The sender holds an agent key; the ceiling is against a runaway, not a
 *       stranger, and is set well above anything a real scan produces.
 * </ul>
 * All three are properties, so an estate that needs more can say so.
 */
@Component
public class RequestBodyLimitFilter extends OncePerRequestFilter {

    private final DataSize webhook;
    private final DataSize vexIngest;
    private final DataSize agentResult;

    public RequestBodyLimitFilter(
            @Value("${vectispire.http.max-body.ticket-webhook:1MB}") DataSize webhook,
            @Value("${vectispire.http.max-body.vex-ingest:16MB}") DataSize vexIngest,
            @Value("${vectispire.http.max-body.agent-result:256MB}") DataSize agentResult) {
        this.webhook = webhook;
        this.vexIngest = vexIngest;
        this.agentResult = agentResult;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Optional<Long> limit = limitFor(request);
        if (limit.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        long ceiling = limit.get();
        if (request.getContentLengthLong() > ceiling) {
            response.setStatus(HttpStatus.CONTENT_TOO_LARGE.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(
                    "{\"message\":\"The request body is larger than the %d bytes this route accepts.\"}"
                            .formatted(ceiling));
            return;
        }
        chain.doFilter(new Bounded(request, ceiling), response);
    }

    /** The ceiling for this route, or empty when the route reads no raw body. */
    private Optional<Long> limitFor(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return Optional.empty();
        }
        String path = LoginRateLimitFilter.routedPath(request);
        if (path.startsWith(WebhookRateLimitFilter.WEBHOOK_PREFIX)) {
            return Optional.of(webhook.toBytes());
        }
        if (path.equals("/api/v1/vex/ingest")) {
            return Optional.of(vexIngest.toBytes());
        }
        if (path.startsWith("/api/v1/agent/jobs/") && path.endsWith("/result")) {
            return Optional.of(agentResult.toBytes());
        }
        return Optional.empty();
    }

    /** The request, with an input stream that counts. */
    private static final class Bounded extends HttpServletRequestWrapper {
        private final long ceiling;
        private ServletInputStream stream;

        Bounded(HttpServletRequest request, long ceiling) {
            super(request);
            this.ceiling = ceiling;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                stream = new Counting(super.getInputStream(), ceiling);
            }
            return stream;
        }
    }

    private static final class Counting extends ServletInputStream {
        private final ServletInputStream delegate;
        private final long ceiling;
        private long read;

        Counting(ServletInputStream delegate, long ceiling) {
            this.delegate = delegate;
            this.ceiling = ceiling;
        }

        @Override
        public int read() throws IOException {
            int value = delegate.read();
            if (value >= 0) {
                count(1);
            }
            return value;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int n = delegate.read(buffer, offset, length);
            if (n > 0) {
                count(n);
            }
            return n;
        }

        private void count(int n) {
            read += n;
            if (read > ceiling) {
                throw new RequestBodyTooLargeException(ceiling);
            }
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener listener) {
            delegate.setReadListener(listener);
        }
    }
}
