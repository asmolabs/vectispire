package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.core.inventory.InventoryQueryService;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MvcResult;

/**
 * A refusal answers in its own words only when it was written as one.
 *
 * <p>{@code IllegalArgumentException} used to be 400 and {@code NoSuchElementException} 404, each with
 * its message: a library's internals reached the client, and a defect read as the caller's mistake or
 * as an absence. The deliberate cases are {@link InvalidInputException} and {@link NotFoundException};
 * the bare types are a 500 that quotes a reference and nothing else.
 */
@DisplayName("which refusals speak")
class RefusalTypesRoutesTest extends ApiTestBase {

    private static final String SEARCH = "/api/v1/inventory/search?name=openssl";

    @MockitoSpyBean
    private InventoryQueryService inventory;

    @Autowired
    private IssueRepository issues;

    @Test
    @DisplayName("an unmapped IllegalArgumentException is a 500 that quotes nothing it was thrown with")
    void aBareIllegalArgumentIsAFailure() throws Exception {
        doThrow(new IllegalArgumentException("The given id must not be null"))
                .when(inventory).search(any(), any(), any());

        JsonNode problem = failure(mvc.perform(authenticated(get(SEARCH), asAdmin())).andReturn());
        assertThat(problem.toString()).doesNotContain("given id");
    }

    @Test
    @DisplayName("an unmapped NoSuchElementException is a 500, not an absence")
    void aBareNoSuchElementIsAFailure() throws Exception {
        doThrow(new NoSuchElementException("No value present")).when(inventory).search(any(), any(), any());

        JsonNode problem = failure(mvc.perform(authenticated(get(SEARCH), asAdmin())).andReturn());
        assertThat(problem.toString()).doesNotContain("No value present");
    }

    @Test
    @DisplayName("a refusal written as one keeps its status and its sentence")
    void theDeliberateOnesSpeak() throws Exception {
        doThrow(new InvalidInputException("A component name is required."))
                .when(inventory).search(any(), any(), any());
        MvcResult invalid = mvc.perform(authenticated(get(SEARCH), asAdmin())).andReturn();
        assertThat(invalid.getResponse().getStatus()).isEqualTo(400);
        assertThat(detailOf(invalid)).isEqualTo("A component name is required.");

        doThrow(new NotFoundException("Repository not found.")).when(inventory).search(any(), any(), any());
        MvcResult absent = mvc.perform(authenticated(get(SEARCH), asAdmin())).andReturn();
        assertThat(absent.getResponse().getStatus()).isEqualTo(404);
        assertThat(detailOf(absent)).isEqualTo("Repository not found.");
    }

    @Test
    @DisplayName("an unknown ticketing provider is refused in words, not with the enum's class name")
    void anUnknownTicketingProvider() throws Exception {
        MvcResult result = mvc.perform(authenticated(post("/api/v1/issues/" + issue() + "/tickets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"provider\":\"bugzilla\",\"ticketKey\":\"SEC-1\","
                                + "\"ticketUrl\":\"https://tracker.invalid/SEC-1\"}"))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(detailOf(result))
                .isEqualTo("Unknown ticketing provider \"bugzilla\". Expected one of: jira, github, gitlab.");
    }

    @Test
    @DisplayName("a compliance target whose id is not a number is refused in words, not by the parser")
    void aMalformedComplianceTarget() throws Exception {
        MvcResult result = mvc.perform(authenticated(
                        get("/api/v1/compliance/summary?targetId=repository:abc"), asAdmin()))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(detailOf(result)).isEqualTo("A target is written repository:<id> or container:<id>.");
    }

    private JsonNode failure(MvcResult result) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(500);
        assertThat(result.getResponse().getContentType()).startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        JsonNode problem = json.readTree(result.getResponse().getContentAsString());
        String reference = problem.path("correlationId").asText();
        assertThat(reference).as("the reference the operator searches the log for").isNotBlank();
        assertThat(problem.path("detail").asText()).contains(reference);
        return problem;
    }

    private long issue() {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("fp-refusal-types");
        issue.setIdentifier("CVE-2026-0001");
        issue.setType("vulnerability");
        issue.setSeverity("HIGH");
        issue.setState("open");
        issue.setTriageStatus("untriaged");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
