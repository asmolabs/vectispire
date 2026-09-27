package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.RequestDispatcher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * One error format: every refusal is an RFC 9457 problem, and every problem has a {@code detail}.
 *
 * <p><b>What this pins is the shape, by class of refusal.</b> Before, only the exceptions {@code
 * ApiExceptionHandler} listed answered a problem. Spring's own refusals — an unknown route, a wrong
 * method or media type, a body that is not JSON — and every {@code ResponseStatusException} went to the
 * container's error page, whose body carries no {@code detail}; the chain's 401 had no body at all,
 * its 403 the error page's, and its limiters {@code {"message": …}}. The interface reads {@code
 * detail}, so the sentence each of those carried never reached a screen.
 */
@DisplayName("one error format")
class ProblemDetailsRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("an unknown route is a problem, in words about a route rather than a static file")
    void anUnknownRoute() throws Exception {
        JsonNode problem = problem(authenticated(get("/api/v1/no-such-route"), asAdmin()), 404);
        assertThat(problem.get("detail").asText()).isEqualTo("Nothing is served at this path.");
    }

    @Test
    @DisplayName("a method the route does not take is a problem")
    void aWrongMethod() throws Exception {
        problem(authenticated(delete("/api/v1/auth/me"), asAdmin()), 405);
    }

    @Test
    @DisplayName("a body in a media type the route does not read is a problem")
    void aWrongContentType() throws Exception {
        problem(authenticated(post("/api/v1/repositories"), asAdmin())
                .contentType(MediaType.TEXT_PLAIN)
                .content("x"), 415);
    }

    @Test
    @DisplayName("an Accept the route cannot answer is still answered a problem")
    void anUnacceptableAccept() throws Exception {
        problem(authenticated(get("/api/v1/auth/me"), asAdmin()).accept(MediaType.IMAGE_PNG), 406);
    }

    @Test
    @DisplayName("a body that is not JSON is a problem that does not quote the parser")
    void anUnreadableBody() throws Exception {
        JsonNode problem = problem(authenticated(post("/api/v1/repositories"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{nope"), 400);
        assertThat(problem.get("detail").asText())
                .doesNotContain("Unexpected character")
                .doesNotContain("jackson");
    }

    @Test
    @DisplayName("a path variable of the wrong type is a problem that names no Java type")
    void aTypeMismatch() throws Exception {
        JsonNode problem = problem(authenticated(get("/api/v1/issues/abc"), asAdmin()), 400);
        assertThat(problem.get("detail").asText()).doesNotContain("java.lang");
    }

    @Test
    @DisplayName("a missing required parameter is a problem")
    void aMissingParameter() throws Exception {
        problem(authenticated(get("/api/v1/inventory/search"), asAdmin()), 400);
    }

    @Test
    @DisplayName("a ResponseStatusException's reason is the detail")
    void aResponseStatusExceptionKeepsItsReason() throws Exception {
        JsonNode missing = problem(post("/api/v1/auth/mfa/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"), 400);
        assertThat(missing.get("detail").asText()).isEqualTo("MFA token and verification code are required.");

        JsonNode refused = problem(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"nobody-here\",\"password\":\"wrong\"}"), 401);
        assertThat(refused.get("detail").asText()).isEqualTo("Invalid credentials.");
    }

    @Test
    @DisplayName("the chain's 401 is a problem, with no challenge a browser would prompt on")
    void theChainsUnauthenticated() throws Exception {
        MvcResult result = mvc.perform(get("/api/v1/issues")).andReturn();
        assertProblem(result, 401);
        assertThat(result.getResponse().getHeader("WWW-Authenticate")).isNull();
    }

    @Test
    @DisplayName("the chain's 403 is a problem, and names no role")
    void theChainsForbidden() throws Exception {
        JsonNode problem = problem(authenticated(get("/api/v1/users"), asReader()), 403);
        assertThat(problem.get("detail").asText()).doesNotContain("ADMIN").doesNotContain("SUPERUSER");
    }

    @Test
    @DisplayName("the sign-in limiter's 429 is a problem carrying the wait, in the body the sign-in screen reads")
    void theSignInLimiter() throws Exception {
        MvcResult limited = null;
        for (int attempt = 0; attempt < 30 && limited == null; attempt++) {
            MvcResult result = mvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"burst-" + attempt + "\",\"password\":\"wrong\"}"))
                    .andReturn();
            if (result.getResponse().getStatus() == 429) {
                limited = result;
            }
        }
        assertThat(limited).as("thirty sign-ins from one address must meet the limiter").isNotNull();
        JsonNode problem = assertProblem(limited, 429);
        assertThat(problem.get("retryAfterSeconds").asLong()).isPositive();
        assertThat(limited.getResponse().getHeader("Retry-After")).isNotBlank();
    }

    @Test
    @DisplayName("the body limit's 413 is a problem, and so encoded that a client parses it")
    void theBodyLimit() throws Exception {
        MvcResult result = mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new byte[2 * 1024 * 1024]))
                .andReturn();
        assertProblem(result, 413);
    }

    @Test
    @DisplayName("the container's error page answers a problem's members, and a 500 quotes nothing it was thrown with")
    void theErrorPage() throws Exception {
        MvcResult result = mvc.perform(authenticated(get("/error"), asAdmin())
                        .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, 500)
                        .requestAttr(RequestDispatcher.ERROR_REQUEST_URI, "/api/v1/issues")
                        .requestAttr(RequestDispatcher.ERROR_EXCEPTION,
                                new IllegalStateException("column t_secret.value is not unique")))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(500);
        JsonNode problem = json.readTree(result.getResponse().getContentAsString());
        assertThat(problem.get("status").asInt()).isEqualTo(500);
        assertThat(problem.get("instance").asText()).isEqualTo("/api/v1/issues");
        String reference = problem.get("correlationId").asText();
        assertThat(problem.get("detail").asText()).contains(reference).doesNotContain("t_secret");
        assertThat(result.getResponse().getContentAsString()).doesNotContain("t_secret").doesNotContain("trace");
    }

    @Test
    @DisplayName("an absent repository and a hidden one read alike on the scorecard, now that the reason is sent")
    void absentAndHiddenReadAlike() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/hidden.git");
        repository.setBranch("main");
        long hidden = repositories.save(repository).getId();
        String reader = asReader();

        JsonNode ofHidden = problem(authenticated(get("/api/v1/scorecards/repositories/" + hidden), reader), 404);
        JsonNode ofAbsent = problem(authenticated(get("/api/v1/scorecards/repositories/999999"), reader), 404);
        JsonNode ofAbsentToAll = problem(authenticated(get("/api/v1/scorecards/repositories/999999"), asAdmin()), 404);

        assertThat(ofHidden.get("detail")).isEqualTo(ofAbsent.get("detail")).isEqualTo(ofAbsentToAll.get("detail"));
    }

    private JsonNode problem(MockHttpServletRequestBuilder request, int status) throws Exception {
        return assertProblem(mvc.perform(request).andReturn(), status);
    }

    private JsonNode assertProblem(MvcResult result, int status) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(status);
        assertThat(result.getResponse().getContentType())
                .as("the media type RFC 9457 names")
                .startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        JsonNode problem = json.readTree(result.getResponse().getContentAsString());
        assertThat(problem.get("status").asInt()).isEqualTo(status);
        assertThat(problem.path("detail").asText()).as("a sentence the interface can show").isNotBlank();
        return problem;
    }
}
