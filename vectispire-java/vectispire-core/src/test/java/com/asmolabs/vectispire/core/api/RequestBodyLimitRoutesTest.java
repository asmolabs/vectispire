package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.ServletContext;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * The default ceiling on every request body, through the real filter chain and the real converters.
 *
 * <p>Until it existed, only the webhook, the VEX import, the SARIF import, an agent's result and the
 * sign-in routes were bounded; every other JSON route read whatever it was sent, to the end.
 */
@DisplayName("the size of what an ordinary route accepts")
class RequestBodyLimitRoutesTest extends ApiTestBase {

    private static final int MEBIBYTE = 1024 * 1024;

    /** An empty JSON object, padded with whitespace to exactly {@code size} bytes: valid, and useless. */
    private static String paddedObject(int size) {
        return "{" + " ".repeat(size - 2) + "}";
    }

    @Test
    @DisplayName("a body past a megabyte on an ordinary route is a 413, in the error shape every refusal has")
    void anOversizedBodyOnAnOrdinaryRouteIsRefused() throws Exception {
        MockHttpServletResponse response = mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(paddedObject(MEBIBYTE + 1)))
                .andReturn().getResponse();

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentType()).startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        JsonNode problem = json.readTree(response.getContentAsString());
        assertThat(problem.path("status").asInt()).isEqualTo(413);
        assertThat(problem.path("detail").asText()).contains(String.valueOf(MEBIBYTE));
    }

    @Test
    @DisplayName("a body of a megabyte exactly is still read, to the end, by the service")
    void aBodyAtTheCeilingIsRead() throws Exception {
        MockHttpServletResponse response = mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(paddedObject(MEBIBYTE)))
                .andReturn().getResponse();

        // The service's own refusal of an empty map: the body was parsed whole and reached it.
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(json.readTree(response.getContentAsString()).path("detail").asText())
                .isEqualTo("No setting supplied.");
    }

    @Test
    @DisplayName("a body that declares no length is counted while the converter reads it, and refused 413")
    void aChunkedBodyIsCountedThroughTheConverter() throws Exception {
        // The converter catches IOException and would call an overflow malformed JSON; the counted
        // stream's refusal has to cross Jackson and reach the error handler as what it is.
        MockHttpServletResponse response = mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(paddedObject(2 * MEBIBYTE))
                        .with(withoutDeclaredLength()))
                .andReturn().getResponse();

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(json.readTree(response.getContentAsString()).path("detail").asText())
                .contains(String.valueOf(MEBIBYTE));
    }

    @Test
    @DisplayName("the routes with a larger ceiling of their own keep it: the default does not clamp them")
    void largerCeilingsAreNotClamped() throws Exception {
        String padding = " ".repeat(2 * MEBIBYTE);

        int vex = mvc.perform(authenticated(post("/api/v1/vex/ingest"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"@context\":\"https://openvex.dev/ns\"," + padding + "\"statements\":[]}"))
                .andReturn().getResponse().getStatus();
        assertThat(vex).as("VEX import, 16 MB").isEqualTo(200);

        // Four files under RuleSet's per-file limit, well past the default together.
        String content = "rules:\n  - id: sqli\n" + ("# " + "x".repeat(1_000) + "\n").repeat(400);
        List<Map<String, String>> files = List.of(
                Map.of("name", "a.yaml", "content", content),
                Map.of("name", "b.yaml", "content", content),
                Map.of("name", "c.yaml", "content", content),
                Map.of("name", "d.yaml", "content", content));
        String upload = write(Map.of("name", "large", "files", files));
        assertThat(upload.length()).isGreaterThan(MEBIBYTE);
        int ruleSet = mvc.perform(authenticated(post("/api/v1/rule-sets"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(upload))
                .andReturn().getResponse().getStatus();
        assertThat(ruleSet).as("rule-set upload, 64 MB").isEqualTo(200);

        // The ceiling is applied before the credential is read, so a route still bounded by the
        // default would answer 413 here, and one with its own larger ceiling reaches the refusal of
        // the missing key.
        int result = mvc.perform(post("/api/v1/agent/jobs/1/result")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(paddedObject(2 * MEBIBYTE)))
                .andReturn().getResponse().getStatus();
        assertThat(result).as("agent result, 256 MB").isEqualTo(401);

        int sarif = mvc.perform(post("/api/v1/repositories/1/sarif-imports")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(paddedObject(2 * MEBIBYTE)))
                .andReturn().getResponse().getStatus();
        assertThat(sarif).as("SARIF import, 32 MB").isEqualTo(401);
    }

    /**
     * MockMvc always declares the length of the content it was given. This hands the chain a copy of
     * the request that hides it, the way a chunked body arrives.
     */
    private static RequestPostProcessor withoutDeclaredLength() {
        return original -> {
            ServletContext context = original.getServletContext();
            MockHttpServletRequest chunked = new MockHttpServletRequest(context, original.getMethod(), original.getRequestURI()) {
                @Override
                public int getContentLength() {
                    return -1;
                }

                @Override
                public long getContentLengthLong() {
                    return -1;
                }
            };
            chunked.setContextPath(original.getContextPath());
            chunked.setServletPath(original.getServletPath());
            chunked.setPathInfo(original.getPathInfo());
            chunked.setContent(original.getContentAsByteArray());
            chunked.setContentType(original.getContentType());
            chunked.setCharacterEncoding(original.getCharacterEncoding());
            chunked.setRemoteAddr(original.getRemoteAddr());
            for (String name : Collections.list(original.getHeaderNames())) {
                if ("Content-Length".equalsIgnoreCase(name)) {
                    continue;
                }
                for (String value : Collections.list(original.getHeaders(name))) {
                    chunked.addHeader(name, value);
                }
            }
            for (String name : Collections.list(original.getAttributeNames())) {
                chunked.setAttribute(name, original.getAttribute(name));
            }
            return chunked;
        };
    }
}
