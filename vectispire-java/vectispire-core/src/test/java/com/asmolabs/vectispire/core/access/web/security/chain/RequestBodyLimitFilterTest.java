package com.asmolabs.vectispire.core.access.web.security.chain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.unit.DataSize;

/**
 * The body ceiling, on the one path the HTTP suite cannot reach.
 *
 * <p>MockMvc always declares a {@code Content-Length}, so the suite only exercises the refusal made
 * before reading. A chunked body declares none and is counted as it is read; that is tested here,
 * with a request that hides its length.
 */
@DisplayName("the request body ceiling")
class RequestBodyLimitFilterTest {

    private final RequestBodyLimitFilter filter =
            new RequestBodyLimitFilter(DataSize.ofBytes(10), DataSize.ofBytes(20), DataSize.ofBytes(30), DataSize.ofBytes(40),
                    DataSize.ofBytes(50), DataSize.ofBytes(70), DataSize.ofBytes(80), DataSize.ofBytes(60),
                    DataSize.ofBytes(5));

    @Test
    @DisplayName("a body with no declared length is refused as soon as it passes the ceiling")
    void aChunkedBodyIsCounted() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/tickets/webhook/jira");
        request.setContent("x".repeat(11).getBytes());
        HttpServletRequest chunked = new HttpServletRequestWrapper(request) {
            @Override
            public long getContentLengthLong() {
                return -1;
            }

            @Override
            public int getContentLength() {
                return -1;
            }
        };

        assertThatThrownBy(() -> filter.doFilter(chunked, new MockHttpServletResponse(),
                        (req, res) -> req.getInputStream().readAllBytes()))
                .isInstanceOf(com.asmolabs.vectispire.core.access.web.security.RequestBodyTooLargeException.class);
    }

    @Test
    @DisplayName("each route with a ceiling of its own keeps it whole, above the default")
    void eachRouteItsCeiling() throws Exception {
        // Every ceiling here is above the default of 5: a route's own is taken instead of the
        // default, never bounded by it.
        assertThat(declared("/api/v1/tickets/webhook/gitlab", 11)).isEqualTo(413);
        assertThat(declared("/api/v1/tickets/webhook/gitlab", 10)).isEqualTo(200);
        assertThat(declared("/api/v1/vex/ingest", 21)).isEqualTo(413);
        assertThat(declared("/api/v1/vex/ingest", 20)).isEqualTo(200);
        assertThat(declared("/api/v1/agent/jobs/42/result", 31)).isEqualTo(413);
        assertThat(declared("/api/v1/agent/jobs/42/result", 30)).isEqualTo(200);
        assertThat(declared("/api/v1/repositories/7/sarif-imports", 51)).isEqualTo(413);
        assertThat(declared("/api/v1/repositories/7/sarif-imports", 50)).isEqualTo(200);
        assertThat(declared("/api/v1/repositories/7/coverage-imports", 71)).isEqualTo(413);
        assertThat(declared("/api/v1/repositories/7/coverage-imports", 70)).isEqualTo(200);
        assertThat(declared("/api/v1/repositories/7/test-report-imports", 81)).isEqualTo(413);
        assertThat(declared("/api/v1/repositories/7/test-report-imports", 80)).isEqualTo(200);
        assertThat(declared("/api/v1/rule-sets", 61)).isEqualTo(413);
        assertThat(declared("/api/v1/rule-sets", 60)).isEqualTo(200);
    }

    @Test
    @DisplayName("every other route, whatever its method, takes the default")
    void everyOtherRouteTakesTheDefault() throws Exception {
        for (String method : new String[] {"POST", "PUT", "PATCH", "DELETE"}) {
            assertThat(declared(method, "/api/v1/settings", 6)).as(method).isEqualTo(413);
            assertThat(declared(method, "/api/v1/settings", 5)).as(method).isEqualTo(200);
        }
        // A route's own ceiling is a POST's: another method on the same path is an ordinary request.
        assertThat(declared("PUT", "/api/v1/vex/ingest", 6)).isEqualTo(413);
        assertThat(declared("/api/v1/rule-sets/3/activate", 6)).as("not the upload").isEqualTo(413);
    }

    @Test
    @DisplayName("a chunked body on an ordinary route is counted against the default")
    void aChunkedBodyTakesTheDefault() {
        MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/api/v1/settings");
        request.setContent("x".repeat(6).getBytes());

        assertThatThrownBy(() -> filter.doFilter(hidingItsLength(request), new MockHttpServletResponse(),
                        (req, res) -> req.getInputStream().readAllBytes()))
                .isInstanceOf(com.asmolabs.vectispire.core.access.web.security.RequestBodyTooLargeException.class);
    }

    @Test
    @DisplayName("the refusal made before reading is a problem document, like the one made while reading")
    void theEarlyRefusalIsAProblem() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/api/v1/settings");
        request.setContent("x".repeat(6).getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (req, res) -> {});

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(response.getContentAsString())
                .contains("\"status\":413")
                .contains("\"detail\":\"The request body is larger than the 5 bytes this route accepts.\"");
    }

    private static HttpServletRequest hidingItsLength(HttpServletRequest request) {
        return new HttpServletRequestWrapper(request) {
            @Override
            public long getContentLengthLong() {
                return -1;
            }

            @Override
            public int getContentLength() {
                return -1;
            }
        };
    }

    @Test
    @DisplayName("the sign-in routes anybody may post to have a ceiling of their own")
    void theSignInRoutesAreBounded() throws Exception {
        // Read by the JSON converter with no ceiling but the container's, on routes that need no
        // credential: the webhook's buffering, offered to anyone.
        for (String path : new String[] {"/api/v1/auth/login", "/api/v1/auth/mfa/verify", "/api/v1/auth/session/exchange"}) {
            assertThat(declared(path, 41)).as(path).isEqualTo(413);
            assertThat(declared(path, 40)).as(path).isEqualTo(200);
        }
    }

    private int declared(String path, int length) throws Exception {
        return declared("POST", path, length);
    }

    private int declared(String method, String path, int length) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setContent("x".repeat(length).getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reached = new AtomicBoolean();
        filter.doFilter(request, response, (req, res) -> {
            req.getInputStream().readAllBytes();
            reached.set(true);
        });
        return reached.get() ? 200 : response.getStatus();
    }
}
