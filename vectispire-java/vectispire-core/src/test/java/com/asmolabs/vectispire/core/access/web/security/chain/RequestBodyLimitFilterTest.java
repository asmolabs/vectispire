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
            new RequestBodyLimitFilter(DataSize.ofBytes(10), DataSize.ofBytes(20), DataSize.ofBytes(30));

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
                .isInstanceOf(RequestBodyLimitFilter.RequestBodyTooLargeException.class);
    }

    @Test
    @DisplayName("each raw-body route has its own ceiling, and other routes none")
    void eachRouteItsCeiling() throws Exception {
        assertThat(declared("/api/v1/tickets/webhook/gitlab", 11)).isEqualTo(413);
        assertThat(declared("/api/v1/tickets/webhook/gitlab", 10)).isEqualTo(200);
        assertThat(declared("/api/v1/vex/ingest", 21)).isEqualTo(413);
        assertThat(declared("/api/v1/vex/ingest", 20)).isEqualTo(200);
        assertThat(declared("/api/v1/agent/jobs/42/result", 31)).isEqualTo(413);
        assertThat(declared("/api/v1/agent/jobs/42/result", 30)).isEqualTo(200);
        assertThat(declared("/api/v1/settings/ticket-token", 1_000)).as("not a raw-body route").isEqualTo(200);
    }

    private int declared(String path, int length) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
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
