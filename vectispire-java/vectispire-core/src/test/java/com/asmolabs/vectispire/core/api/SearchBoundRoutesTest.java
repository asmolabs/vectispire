package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The free-text searches of the list routes, bounded by one figure ({@link BoundedText#SEARCH_MAX}).
 *
 * <p>The backlog's {@code identifier} was refused past its column while the {@code search} beside it went to
 * the engine as a {@code like} pattern of any length; the audit log's search, the inventory's component name
 * and the blast radius's {@code q} did the same. Each is refused past the figure in words — the 400's
 * {@code detail} names the parameter and the figure — trimmed before it is measured, and blank where blank
 * asked nothing before. Through the real controllers, on MySQL: the bound is the service's, and a route
 * that skipped the service's parsing would show here.
 */
@DisplayName("the list routes' free-text searches, bounded by one figure")
class SearchBoundRoutesTest extends ApiTestBase {

    private static final int MAX = BoundedText.SEARCH_MAX;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @ParameterizedTest(name = "{0}?{1}=")
    @CsvSource({
        "/api/v1/issues, search",
        "/api/v1/audit-log, search",
        "/api/v1/blast-radius/explore, q",
        "/api/v1/inventory/search, name",
        "/api/v1/inventory/versions, name",
    })
    @DisplayName("one character past the figure is a 400 naming the parameter; the figure itself, padded, is answered")
    void refusedPastTheFigure(String route, String parameter) throws Exception {
        MvcResult refused = mvc.perform(authenticated(get(route).param(parameter, "x".repeat(MAX + 1)), asAdmin()))
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(detailOf(refused)).isEqualTo(parameter + " is longer than " + MAX + " characters.");

        // Measured after the trim: the spaces a pasted value carries are not the caller's search.
        mvc.perform(authenticated(get(route).param(parameter, "  " + "x".repeat(MAX) + "  "), asAdmin()))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("the backlog's search still matches trimmed and case aside, and a blank one is no filter")
    void theBacklogsSearchKeepsItsMeaning() throws Exception {
        String identifier = "CVE-" + System.nanoTime();
        long repository = repository();
        issue(repository, identifier);

        assertThat(identifiers(list("  " + identifier.toLowerCase(Locale.ROOT) + "  "))).containsExactly(identifier);

        long everything = json.readTree(mvc.perform(authenticated(get("/api/v1/issues"), asAdmin()))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString())
                .path("total").asLong();
        assertThat(everything).isPositive();
        assertThat(list("   ").path("total").asLong()).isEqualTo(everything);
    }

    @Test
    @DisplayName("the audit log's search is the trail whole when blank")
    void theAuditSearchBlankIsTheTrail() throws Exception {
        long everything = auditTotal(null);
        assertThat(auditTotal("   ")).isEqualTo(everything);
    }

    // ------------------------------------------------------------------------------ helpers

    private JsonNode list(String search) throws Exception {
        var request = get("/api/v1/issues").param("limit", "500").param("search", search);
        return json.readTree(mvc.perform(authenticated(request, asAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private long auditTotal(String search) throws Exception {
        var request = get("/api/v1/audit-log");
        if (search != null) {
            request.param("search", search);
        }
        return json.readTree(mvc.perform(authenticated(request, asAdmin()))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString())
                .path("total").asLong();
    }

    private static List<String> identifiers(JsonNode page) {
        return StreamSupport.stream(page.path("items").spliterator(), false)
                .map(item -> item.path("identifier").asText())
                .toList();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/search-bound-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void issue(long repoId, String identifier) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
