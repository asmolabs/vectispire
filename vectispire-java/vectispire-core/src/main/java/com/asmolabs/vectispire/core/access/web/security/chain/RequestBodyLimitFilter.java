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
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A ceiling on every request body, applied before anything parses it.
 *
 * <p><b>Why a filter, and not a container setting.</b> Tomcat's {@code maxPostSize} and Spring's
 * multipart limits apply to form and multipart bodies only; a {@code @RequestBody} — a record, a
 * {@code String} or a {@code byte[]} — is read by a message converter to the end of the stream,
 * whatever its length. So the anonymous tracker webhook, the VEX import and an agent's result had no
 * ceiling at all at first, and every other JSON route still had none after those were given one: a
 * signed-in account, or a leaked integration key, could make the process buffer as much as it cared
 * to send into a request that needs a few hundred bytes. Nothing else in the stack bounds them, and
 * only a filter sees the body before the converter does.
 *
 * <p><b>Two checks.</b> A declared {@code Content-Length} over the ceiling is answered 413 at once,
 * without reading a byte. A body with no declared length — chunked — is counted as the converter
 * reads it, and refused the moment it passes the ceiling; {@link RequestBodyTooLargeException} is
 * unchecked on purpose, because the converters catch {@code IOException} and would turn it into a
 * 400 that says the JSON was malformed. The header is only ever a reason to refuse early, never a
 * reason to stop counting.
 *
 * <p><b>The limits, and why each.</b> A route with a ceiling of its own takes it <i>instead of</i>
 * the default, never the smaller of the two: the default is for the routes nobody measured, not a
 * clamp on the ones that were.
 * <ul>
 *   <li>Default, 1 MB, every other route and every method: a triage, a grant list, a setting, a gate
 *       request or a SCIM user is at most tens of kilobytes, and a bulk triage of ten thousand ids
 *       fits many times over.
 *   <li>Webhook, 1 MB: a Jira or GitLab issue event with its changelog is tens of kilobytes; ten
 *       times the largest seen leaves room and still stops an anonymous client early.
 *   <li>VEX import, 16 MB: an OpenVEX or CycloneDX VEX document for a large product runs to a few
 *       megabytes; it is uploaded by a signed-in account, and parsed whole.
 *   <li>SARIF import, 32 MB: an internal tool's report for one repository — SonarQube's or a CI's —
 *       runs to a few megabytes; the sender holds a declared source's key, and the document is parsed
 *       whole. The service holds the same limit where it reads the bytes.
 *   <li>Coverage import, 16 MB: a JaCoCo or Cobertura XML report for a large repository runs to a few
 *       megabytes (a counter per method, a line per source line); an lcov tracefile is smaller. The
 *       sender holds a declared source's key, the service holds the same limit, and only the totals
 *       are kept (decision 0032 §7).
 *   <li>Test-report import, 32 MB: a JUnit document, or a zip of one per test class, whose failures
 *       carry stack traces and captured output. The zip is bounded again once inflated — entries and
 *       bytes — by the reader, since 32 MB of deflate is gigabytes of XML.
 *   <li>Rule-set upload, 64 MB, {@code POST /api/v1/rule-sets}: {@code RuleSet} accepts up to 32 MB
 *       of rule files, and the JSON carrying them escapes every quote and line break of their YAML. A
 *       set at the domain's own limit must still arrive, or this would be a second, smaller limit
 *       that nobody states.
 *   <li>Agent result, 256 MB: the result carries the SBOM, and a large container image's is tens of
 *       megabytes of JSON. The sender holds an agent key; the ceiling is against a runaway, not a
 *       stranger, and is set well above anything a real scan produces.
 *   <li>Sign-in, 16 KB, every {@code POST} under {@code /api/v1/auth/}: a login, a one-time code, a
 *       session exchange or a password change is a few hundred bytes of JSON. Three of these routes
 *       are open to anyone, and their bodies were read by the JSON converter with no ceiling but the
 *       container's — the same buffering as the webhook's, offered to a client with no credential.
 * </ul>
 * All nine are properties, so an estate that needs more can say so. There is no multipart route
 * today. One added later would have its parts parsed by the container from the raw request, past the
 * counting stream, so only the declared length would bound it here and Spring's multipart limits
 * would be the real ones — give it a line of its own rather than trust the default.
 */
@Component
public class RequestBodyLimitFilter extends OncePerRequestFilter {

    private final DataSize webhook;
    private final DataSize vexIngest;
    private final DataSize agentResult;
    private final DataSize signIn;
    private final DataSize sarifImport;
    private final DataSize coverageImport;
    private final DataSize testReportImport;
    private final DataSize ruleSetUpload;
    private final DataSize fallback;

    /** The prefix of the sign-in routes, three of them open to anyone. */
    static final String SIGN_IN_PREFIX = "/api/v1/auth/";

    public RequestBodyLimitFilter(
            @Value("${vectispire.http.max-body.ticket-webhook:1MB}") DataSize webhook,
            @Value("${vectispire.http.max-body.vex-ingest:16MB}") DataSize vexIngest,
            @Value("${vectispire.http.max-body.agent-result:256MB}") DataSize agentResult,
            @Value("${vectispire.http.max-body.sign-in:16KB}") DataSize signIn,
            @Value("${vectispire.http.max-body.sarif-import:32MB}") DataSize sarifImport,
            @Value("${vectispire.http.max-body.coverage-import:16MB}") DataSize coverageImport,
            @Value("${vectispire.http.max-body.test-report-import:32MB}") DataSize testReportImport,
            @Value("${vectispire.http.max-body.rule-set-upload:64MB}") DataSize ruleSetUpload,
            @Value("${vectispire.http.max-body.default:1MB}") DataSize fallback) {
        this.webhook = webhook;
        this.vexIngest = vexIngest;
        this.agentResult = agentResult;
        this.signIn = signIn;
        this.sarifImport = sarifImport;
        this.coverageImport = coverageImport;
        this.testReportImport = testReportImport;
        this.ruleSetUpload = ruleSetUpload;
        this.fallback = fallback;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        long ceiling = ownLimit(request).orElse(fallback).toBytes();
        if (request.getContentLengthLong() > ceiling) {
            // RFC 9457, the shape `ApiExceptionHandler` gives the same refusal found while reading:
            // the client reads `detail`, and one 413 must not answer in two shapes depending on
            // which of the two checks caught the body.
            ProblemResponses.write(request, response, HttpStatus.CONTENT_TOO_LARGE,
                    new RequestBodyTooLargeException(ceiling).getMessage());
            return;
        }
        chain.doFilter(new Bounded(request, ceiling), response);
    }

    /**
     * The route's own ceiling, or empty when it has none and takes the default. Its own replaces the
     * default: a route listed here with more than the default keeps all of it.
     */
    private Optional<DataSize> ownLimit(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return Optional.empty();
        }
        String path = LoginRateLimitFilter.routedPath(request);
        if (path.startsWith(WebhookRateLimitFilter.WEBHOOK_PREFIX)) {
            return Optional.of(webhook);
        }
        if (path.equals("/api/v1/vex/ingest")) {
            return Optional.of(vexIngest);
        }
        if (path.startsWith("/api/v1/agent/jobs/") && path.endsWith("/result")) {
            return Optional.of(agentResult);
        }
        if (path.startsWith("/api/v1/repositories/") && path.endsWith("/sarif-imports")) {
            return Optional.of(sarifImport);
        }
        if (path.startsWith("/api/v1/repositories/") && path.endsWith("/coverage-imports")) {
            return Optional.of(coverageImport);
        }
        if (path.startsWith("/api/v1/repositories/") && path.endsWith("/test-report-imports")) {
            return Optional.of(testReportImport);
        }
        if (path.equals("/api/v1/rule-sets")) {
            return Optional.of(ruleSetUpload);
        }
        if (path.startsWith(SIGN_IN_PREFIX)) {
            return Optional.of(signIn);
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
