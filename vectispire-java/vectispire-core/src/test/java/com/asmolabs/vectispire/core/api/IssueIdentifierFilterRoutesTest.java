package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * {@code GET /api/v1/issues?identifier=…}: the issues carrying one identifier, exactly.
 *
 * <p>The links that mean "this CVE" — the remediation plan's, the OWASP report's — opened the list with
 * {@code search}, which matches a substring: the issues of {@code CVE-2021-4428} came with those of
 * {@code CVE-2021-44228}. The cases pin the exact match, the case rule the search shares, and that the
 * filter narrows beside the visibility and never in its place.
 */
@DisplayName("the issues list, filtered by one identifier exactly")
class IssueIdentifierFilterRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private SettingsService settings;

    @Autowired
    private UserRepository users;

    @Test
    @DisplayName("the identifier and not its neighbours, whatever the case asked; search still matches the substring")
    void exactlyTheIdentifier() throws Exception {
        String asked = "CVE-" + System.nanoTime();
        String neighbour = asked + "8";
        long repository = repository();
        issue(repository, asked);
        issue(repository, asked);
        issue(repository, neighbour);

        JsonNode exact = list("identifier=" + asked, asAdmin());
        assertThat(identifiers(exact)).containsExactly(asked, asked);
        assertThat(exact.path("total").asLong()).as("the count shares the page's filters").isEqualTo(2);
        assertThat(identifiers(list(Map.of("identifier", " " + asked.toLowerCase(Locale.ROOT) + " "), asAdmin())))
                .as("case aside and trimmed, as the search reads the column")
                .containsExactly(asked, asked);
        assertThat(identifiers(list("search=" + asked, asAdmin())))
                .as("the search keeps its substring")
                .containsExactlyInAnyOrder(asked, asked, neighbour);
    }

    @Test
    @DisplayName("another account's issue carrying the same identifier is not listed to a restricted reader")
    void withinTheVisibility() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        try {
            String asked = "CVE-" + System.nanoTime();
            long mine = repository();
            long theirs = repository();
            long ownIssue = issue(mine, asked);
            issue(theirs, asked);
            String username = "identifier-reader-" + System.nanoTime();
            String reader = tokenFor(username, Role.USER, false);
            long readerId = users.findByUsername(username).orElseThrow().getId();
            mvc.perform(authenticated(put("/api/v1/users/" + readerId + "/targets"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(List.of(Map.of("kind", "repository", "id", mine)))))
                    .andExpect(status().isOk());

            JsonNode seen = list("identifier=" + asked, reader);
            assertThat(StreamSupport.stream(seen.path("items").spliterator(), false)
                            .map(item -> item.path("id").asLong())
                            .toList())
                    .containsExactly(ownIssue);
            assertThat(seen.path("total").asLong()).isEqualTo(1);
            assertThat(identifiers(list("identifier=" + asked, asAdmin())))
                    .as("both exist: the administrator is listed both")
                    .hasSize(2);
        } finally {
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());
        }
    }

    @Test
    @DisplayName("an identifier longer than the column is refused in words; a blank one asks nothing")
    void boundedByTheColumn() throws Exception {
        var refused = mvc.perform(authenticated(get("/api/v1/issues?identifier=" + "C".repeat(256)), asAdmin()))
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(detailOf(refused)).contains("identifier").contains("255");

        mvc.perform(authenticated(get("/api/v1/issues?identifier=" + "C".repeat(255)), asAdmin()))
                .andExpect(status().isOk());
        issue(repository(), "CVE-" + System.nanoTime());
        long everything = list(Map.of(), asAdmin()).path("total").asLong();
        assertThat(everything).isPositive();
        assertThat(list(Map.of("identifier", "  "), asAdmin()).path("total").asLong()).isEqualTo(everything);
    }

    // ------------------------------------------------------------------------------ helpers

    private JsonNode list(String query, String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/issues?limit=500&" + query), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    /** The parameters set one by one, so that a space reaches the route as a space. */
    private JsonNode list(Map<String, String> parameters, String token) throws Exception {
        var request = get("/api/v1/issues").param("limit", "500");
        parameters.forEach(request::param);
        return json.readTree(mvc.perform(authenticated(request, token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private static List<String> identifiers(JsonNode page) {
        return StreamSupport.stream(page.path("items").spliterator(), false)
                .map(item -> item.path("identifier").asText())
                .toList();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/identifier-filter-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long issue(long repoId, String identifier) {
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
        return issues.save(issue).getId();
    }
}
