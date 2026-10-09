package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.compliance.OwaspReport;
import com.asmolabs.vectispire.core.compliance.internal.EvidenceIdentifiers;
import com.asmolabs.vectispire.core.compliance.internal.OwaspReportLinks;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * What {@code GET /api/v1/repositories/{id}/owasp-review} carries for its screen to link with: a code
 * on each category heading, the backlog's count per category, and the issues behind the identifiers the
 * model was shown.
 *
 * <p>What the screen depends on: the figure on a category's link is the length of the list that link
 * opens — asserted against the backlog route itself, category by category, rather than against numbers
 * worked out here — an identifier is linked only when the evidence held it, and none of it describes an
 * issue the caller's backlog would not show them.
 */
@DisplayName("the OWASP report's links to the backlog")
class OwaspReportLinksRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private AiReviewResultRepository reviews;

    @Autowired
    private SettingsService settings;

    @Autowired
    private OwaspReportLinks links;

    @Test
    @DisplayName("each category's figure is the length of the backlog list its link opens, all ten of them")
    void theFigureIsTheListsLength() throws Exception {
        long repository = repository();
        long scan = scan(repository);
        issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-0001", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        // Placed by its type, not its column: the grid puts a vulnerability in A06 whatever the column says,
        // which is where a second, grouped definition of the figure would first disagree with the list.
        issue(repository, FindingType.VULNERABILITY, "A03", "CVE-2026-0002", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-0003", TriageStatus.NOT_AFFECTED, IssueState.OPEN);
        issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-0004", TriageStatus.UNDER_REVIEW, IssueState.RESOLVED);
        issue(repository, FindingType.SAST, "A03", "java.injection", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        issue(repository, FindingType.SAST, "A03", "java.injection.sql", TriageStatus.FIXED, IssueState.OPEN);
        issue(repository, FindingType.IAC, null, "dockerfile.root", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        long elsewhere = repository();
        issue(elsewhere, FindingType.VULNERABILITY, null, "CVE-2026-0001", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        review(repository, scan, "## A06 — Vulnerable and Outdated Components\n\nold.", List.of());

        JsonNode report = report(repository, asAdmin());

        JsonNode figures = report.path("categoryFindings");
        assertThat(fieldNames(figures)).containsExactlyElementsOf(OwaspCoverage.CATEGORIES.keySet());
        for (String category : OwaspCoverage.CATEGORIES.keySet()) {
            assertThat(figures.path(category).asLong())
                    .as("the figure on %s's link", category)
                    .isEqualTo(listed(repository, category, asAdmin()));
        }
        // The list above could agree with a wrong figure by being wrong in the same way; these are the
        // fixture's own answers: the two unsettled open vulnerabilities, the unsettled injection, the
        // container check — and a zero, stated rather than left out.
        assertThat(figures.path("A06").asLong()).isEqualTo(2);
        assertThat(figures.path("A03").asLong()).isEqualTo(1);
        assertThat(figures.path("A05").asLong()).isEqualTo(1);
        assertThat(figures.path("A01").isNumber()).isTrue();
        assertThat(figures.path("A01").asLong()).isZero();
    }

    @Test
    @DisplayName("a category heading carries its code, the key of its figure")
    void aHeadingCarriesItsCode() throws Exception {
        long repository = repository();
        review(repository, scan(repository), "## A03 — Injection\n\nprose.\n\n## Not evidenced", List.of());

        JsonNode blocks = report(repository, asAdmin()).path("blocks");

        assertThat(blocks.get(0).path("kind").asText()).isEqualTo("CATEGORY");
        assertThat(blocks.get(0).path("category").asText()).isEqualTo("A03");
        assertThat(blocks.get(1).path("category").isNull()).as("a paragraph names no category").isTrue();
        assertThat(blocks.get(2).path("category").isNull()).as("an ordinary heading neither").isTrue();
    }

    @Test
    @DisplayName("only an identifier the model was shown is linked — never one its prose invented — and to the issues open now")
    void onlyTheShownIdentifiersAreLinked() throws Exception {
        long repository = repository();
        long scan = scan(repository);
        long single = issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-1000", TriageStatus.UNDER_REVIEW,
                IssueState.OPEN);
        issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-2000", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-2000", TriageStatus.NOT_AFFECTED, IssueState.OPEN);
        issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-3000", TriageStatus.UNDER_REVIEW, IssueState.RESOLVED);
        // A CVE the prose cites, carried by an issue of this very repository, but not in what the model was
        // shown — a finding that appeared since, or a string a description put in the model's mouth.
        issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-6666", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        // The prefix of a shown identifier: matched exactly, or CVE-2026-1 would lead to CVE-2026-1000.
        issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-1", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        long elsewhere = repository();
        issue(elsewhere, FindingType.VULNERABILITY, null, "CVE-2026-1000", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        review(repository, scan, "## A06 — Vulnerable and Outdated Components\n\nCVE-2026-1000, CVE-2026-6666.",
                List.of("CVE-2026-1000", "CVE-2026-2000", "CVE-2026-3000", "rule.nowhere"));

        JsonNode linked = report(repository, asAdmin()).path("issueLinks");

        assertThat(fieldNames(linked)).containsExactly("CVE-2026-1000", "CVE-2026-2000");
        assertThat(linked.path("CVE-2026-1000").path("issueId").asLong()).isEqualTo(single);
        assertThat(linked.path("CVE-2026-1000").path("count").asLong())
                .as("the other repository's issue is not this report's").isEqualTo(1);
        assertThat(linked.path("CVE-2026-2000").path("issueId").isNull()).as("two issues: a list, not one").isTrue();
        assertThat(linked.path("CVE-2026-2000").path("count").asLong())
                .as("settled triage included: the model was shown it").isEqualTo(2);
    }

    @Test
    @DisplayName("a report written before the shown identifiers were recorded says so, rather than that there is nothing to link")
    void notRecordedIsNotNone() throws Exception {
        long repository = repository();
        long scan = scan(repository);
        issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-1000", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        review(repository, scan, "## A06 — Vulnerable\n\nCVE-2026-1000.", null);

        JsonNode report = report(repository, asAdmin());
        assertThat(report.has("issueLinks")).isTrue();
        assertThat(report.path("issueLinks").isNull()).isTrue();

        long recorded = repository();
        review(recorded, scan(recorded), "## A06 — Vulnerable", List.of());
        assertThat(report(recorded, asAdmin()).path("issueLinks").isObject()).isTrue();
        assertThat(report(recorded, asAdmin()).path("issueLinks").isEmpty()).isTrue();
    }

    @Test
    @DisplayName("a reader restricted to their repositories gets another's report as an absence, and their own counted over their own issues")
    void aReaderSeesTheirOwnAlone() throws Exception {
        long mine = repository();
        long theirs = repository();
        issue(mine, FindingType.VULNERABILITY, null, "CVE-2026-1000", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        issue(theirs, FindingType.VULNERABILITY, null, "CVE-2026-1000", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        issue(theirs, FindingType.VULNERABILITY, null, "CVE-2026-9000", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        review(mine, scan(mine), "## A06", List.of("CVE-2026-1000"));
        review(theirs, scan(theirs), "## A06", List.of("CVE-2026-1000", "CVE-2026-9000"));
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String reader = asReader();
        grant(readerId(), List.of(mine));

        // Neither the figures nor the links of a repository they were not given — and refused in the words
        // a repository that does not exist is, so the refusal does not confirm it exists.
        MvcResult hidden = notFound(theirs, reader);
        MvcResult absent = notFound(Long.MAX_VALUE, reader);
        assertThat(detailOf(hidden)).isEqualTo(detailOf(absent));
        assertThat(hidden.getResponse().getContentAsString()).doesNotContain("CVE-2026-9000");

        JsonNode own = report(mine, reader);
        assertThat(own.path("categoryFindings").path("A06").asLong()).isEqualTo(1).isEqualTo(listed(mine, "A06", reader));
        assertThat(own.path("issueLinks").path("CVE-2026-1000").path("count").asLong()).isEqualTo(1);
    }

    /**
     * The route refuses a hidden repository before the figures are counted, so the visibility the counts
     * are asked with cannot be observed through it; asked here, with a visibility that does not reach the
     * repository, it must answer nothing rather than lean on a refusal it cannot see.
     */
    @Test
    @DisplayName("the figures and links are counted with the caller's visibility, not beside it")
    void theCountsCarryTheVisibility() throws Exception {
        long repository = repository();
        long other = repository();
        issue(repository, FindingType.VULNERABILITY, null, "CVE-2026-1000", TriageStatus.UNDER_REVIEW, IssueState.OPEN);
        Visibility elsewhere = Visibility.only(List.of(new ScanTarget.Repository(other)));

        assertThat(links.categoryFindings(repository, elsewhere)).containsEntry("A06", 0L);
        assertThat(links.issueLinks(repository, List.of("CVE-2026-1000"), elsewhere)).isEmpty();
        assertThat(links.categoryFindings(repository, Visibility.everything())).containsEntry("A06", 1L);
        assertThat(links.issueLinks(repository, List.of("CVE-2026-1000"), Visibility.everything()))
                .containsOnlyKeys("CVE-2026-1000")
                .extractingByKey("CVE-2026-1000").extracting(OwaspReport.IssueLink::count).isEqualTo(1L);
    }

    // ------------------------------------------------------------------------------ fixtures

    private JsonNode report(long repository, String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/repositories/" + repository + "/owasp-review"), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private MvcResult notFound(long repository, String token) throws Exception {
        return mvc.perform(authenticated(get("/api/v1/repositories/" + repository + "/owasp-review"), token))
                .andExpect(status().isNotFound())
                .andReturn();
    }

    /** The {@code total} of the list a category's link opens. */
    private long listed(long repository, String category, String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/issues?repository_id=" + repository
                                + "&owasp_category=" + category + "&unsettled=true&limit=500"), token))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString())
                .path("total").asLong();
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new java.util.ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/owasp-links-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long scan(long repoId) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now().minusSeconds(7200));
        return scans.save(scan).getId();
    }

    /** A settled review, its shown identifiers recorded as the request records them — or not at all, as before V84. */
    private void review(long repoId, long scanId, String response, List<String> shown) {
        AiReviewResultEntity row = new AiReviewResultEntity();
        row.setScanId(scanId);
        row.setRepoId(repoId);
        row.setModel("gemma4:e4b");
        row.setPrompt("p");
        row.setInputs("=== DATA ===");
        row.setEvidenceIdentifiers(shown == null ? null : EvidenceIdentifiers.write(shown));
        row.setResponse(response);
        row.setStatus("completed");
        row.setCreatedAt(Instant.now().minusSeconds(60));
        reviews.save(row);
    }

    private long issue(
            long repoId, FindingType type, String owaspCategory, String identifier, TriageStatus triage, IssueState state) {
        Instant seen = Instant.now().minusSeconds(3600);
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(type.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(state.wireName());
        issue.setOwaspCategory(owaspCategory);
        issue.setTriageStatus(triage.wireName());
        issue.setFirstSeenAt(seen);
        issue.setLastSeenAt(seen);
        if (state == IssueState.RESOLVED) {
            issue.resolveAt(seen.plusSeconds(60));
        }
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }

    private void grant(long userId, List<Long> repositories) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(repositories.stream().map(id -> Map.of("kind", "repository", "id", id)).toList())))
                .andExpect(status().isOk());
    }

    /** The reader account's identifier, read back through the administration listing. */
    private long readerId() throws Exception {
        String body = mvc.perform(authenticated(get("/api/v1/users"), asAdmin()))
                .andReturn().getResponse().getContentAsString();
        for (JsonNode node : json.readTree(body).path("users")) {
            if (node.path("username").asText("").startsWith("reader-")) {
                return node.path("id").asLong();
            }
        }
        throw new IllegalStateException("no reader account in the listing");
    }
}
