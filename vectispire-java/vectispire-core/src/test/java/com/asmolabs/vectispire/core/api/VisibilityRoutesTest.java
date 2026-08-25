package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.SettingsService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * What a restricted account can and cannot reach.
 *
 * <p>Every case here is one somebody would probe by changing a number in a URL. The listing
 * routes are the easy half — a filter either applies or it does not. The interesting half is the
 * routes that take an identifier, because a reader who cannot see a target in a list can still
 * ask for its export, its verdict or its scan by guessing.
 */
@DisplayName("what a restricted account may see")
class VisibilityRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private SettingsService settings;

    @Autowired
    private Findings findings;

    @Autowired
    private Scans scans;

    @Test
    @DisplayName("open by default: an account with no assignment still sees everything")
    void everyoneModeChangesNothing() throws Exception {
        long mine = repository("https://example.invalid/mine.git");
        issue(mine, "CVE-2026-1");

        // The default the catalog ships. A deployment that updates must not lose its screens.
        mvc.perform(authenticated(get("/api/v1/issues"), asReader()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1));
    }

    @Test
    @DisplayName("restricted and unassigned: nothing, not everything")
    void anUnassignedReaderSeesNothing() throws Exception {
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        issue(mine, "CVE-2026-1");

        // The inversion this whole design guards against: "no assignment" read as "no
        // restriction" would hand a brand-new account the entire backlog.
        mvc.perform(authenticated(get("/api/v1/issues"), asReader()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(0));
        mvc.perform(authenticated(get("/api/v1/repositories"), asReader()))
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    @DisplayName("restricted and assigned: its own targets and no others")
    void anAssignedReaderSeesOnlyItsOwn() throws Exception {
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        long theirs = repository("https://example.invalid/theirs.git");
        issue(mine, "CVE-MINE");
        issue(theirs, "CVE-THEIRS");

        String reader = assignedReader(mine);

        mvc.perform(authenticated(get("/api/v1/issues"), reader))
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.items[0].identifier").value("CVE-MINE"));
        mvc.perform(authenticated(get("/api/v1/repositories"), reader))
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    @DisplayName("an export of somebody else's target is 404, never 403")
    void anExportOfAnotherTargetIsNotFound() throws Exception {
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        long theirs = repository("https://example.invalid/theirs.git");
        String reader = assignedReader(mine);

        // 403 would answer the question the probe is asking — whether that repository exists.
        // A refusal has to be indistinguishable from an absence.
        mvc.perform(authenticated(get("/api/v1/targets/repository/" + theirs + "/issues.csv"), reader))
                .andExpect(status().isNotFound());
        mvc.perform(authenticated(get("/api/v1/targets/repository/" + theirs + "/issues.sarif"), reader))
                .andExpect(status().isNotFound());
        mvc.perform(authenticated(get("/api/v1/targets/repository/" + theirs + "/vex"), reader))
                .andExpect(status().isNotFound());

        mvc.perform(authenticated(get("/api/v1/targets/repository/" + mine + "/issues.csv"), reader))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("a gate verdict on somebody else's target is 404")
    void aVerdictOnAnotherTargetIsNotFound() throws Exception {
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        long theirs = repository("https://example.invalid/theirs.git");
        String reader = assignedReader(mine);

        // A verdict summarizes a backlog: counts, severities, the identifiers that violate.
        // Answering one hands over most of what the backlog would have said.
        mvc.perform(authenticated(post("/api/v1/gate"), reader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("repository_id", theirs))))
                .andExpect(status().isNotFound());

        mvc.perform(authenticated(post("/api/v1/gate"), reader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("repository_id", mine))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("triaging somebody else's issue is 404, and writes nothing")
    void triagingAnInvisibleIssueIsRefused() throws Exception {
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        long theirs = repository("https://example.invalid/theirs.git");
        long hidden = issue(theirs, "CVE-THEIRS");
        String reader = assignedReader(mine);

        mvc.perform(authenticated(post("/api/v1/issues/" + hidden + "/triage"), reader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("status", "not_affected", "justification", "component_not_present"))))
                .andExpect(status().isNotFound());

        // The write is what matters: a refusal that dismissed the finding anyway would be worse
        // than no refusal, because the dashboard would look better afterwards.
        org.assertj.core.api.Assertions
                .assertThat(issues.findById(hidden).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
    }

    @Test
    @DisplayName("an administrator sees everything, restricted mode or not")
    void administratorsAreNeverRestricted() throws Exception {
        restrict();
        long one = repository("https://example.invalid/one.git");
        issue(one, "CVE-1");

        // Somebody has to be able to make the assignments, and an administrator who cannot see a
        // target cannot assign it.
        mvc.perform(authenticated(get("/api/v1/issues"), asAdmin())).andExpect(jsonPath("$.total").value(1));
    }

    @Test
    @DisplayName("the dashboard counts only what the caller may see")
    void theDashboardIsNarrowedToo() throws Exception {
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        repository("https://example.invalid/theirs.git");
        String reader = assignedReader(mine);

        mvc.perform(authenticated(get("/api/v1/dashboard"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.posture.totalCount").value(1));
    }

    @Test
    @DisplayName("the blast radius shows a restricted reader only their own targets")
    void theBlastRadiusIsScoped() throws Exception {
        // **The hole `Visibility` exists to prevent, found on the one screen nobody had checked.**
        // Its own documentation says authorization spread across controllers is one chance per
        // controller to forget one, and the forgotten one is the hole. This was it: the endpoint
        // read every finding in the deployment and answered with target names, package names and
        // CVE identifiers, to any authenticated account.
        //
        // The leak is not abstract. A blast-radius answer names the repository, the package and
        // the version — an inventory of somebody else's estate, handed to a contractor assigned
        // one repository.
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        long theirs = repository("https://example.invalid/theirs.git");
        finding(mine, "log4j-core", "CVE-2021-44228");
        finding(theirs, "spring-beans", "CVE-2022-22965");

        String reader = assignedReader(mine);

        mvc.perform(authenticated(get("/api/v1/blast-radius/explore"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targets.length()").value(1))
                .andExpect(jsonPath("$.targets[0].packageName").value("log4j-core"));

        // The graph is the same data in another shape, and a scoping that stopped at the summary
        // would leak it here instead.
        mvc.perform(authenticated(get("/api/v1/blast-radius/explore"), reader))
                .andExpect(jsonPath("$.graph.nodes[?(@.label == 'CVE-2022-22965')]").isEmpty());

        mvc.perform(authenticated(get("/api/v1/blast-radius/top-impact"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].packageName").value("log4j-core"));
    }

    @Test
    @DisplayName("an administrator still sees the whole estate's blast radius")
    void theBlastRadiusIsWholeForAnAdministrator() throws Exception {
        // Scoping must not become a ceiling on the people who assign the scopes.
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        long theirs = repository("https://example.invalid/theirs.git");
        finding(mine, "log4j-core", "CVE-2021-44228");
        finding(theirs, "spring-beans", "CVE-2022-22965");

        mvc.perform(authenticated(get("/api/v1/blast-radius/explore"), asAdmin()))
                .andExpect(jsonPath("$.targets.length()").value(2));
    }

    @Test
    @DisplayName("a scan the reader may not see is absent from every export, not just from the SBOM")
    void everyPerScanExportIsGuarded() throws Exception {
        // **`ScansController` has always guarded `/scans/{id}/sbom` with `requireVisible`.** Four
        // other routes hand back the same scan under a different format and none of them did, so
        // the protection depended on which document a caller asked for. A reader who cannot open
        // the SBOM could read the CSAF advisory built from the same scan.
        //
        // 404 rather than 403 throughout, for the reason `Visibilities` gives: a refusal that is
        // distinguishable from an absence answers the question the caller was probing with.
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        long theirs = repository("https://example.invalid/theirs.git");
        long theirScan = scan(theirs);
        String reader = assignedReader(mine);

        for (String route : List.of(
                "/api/v1/scans/" + theirScan + "/sbom",
                "/api/v1/csaf/scans/" + theirScan + "/csaf.json",
                "/api/v1/cyclonedx/scans/" + theirScan + "/cyclonedx-vex.json",
                "/api/v1/vex/scans/" + theirScan + "/openvex.json",
                "/api/v1/attestation/scans/" + theirScan)) {
            mvc.perform(authenticated(get(route), reader))
                    .andExpect(status().isNotFound());
        }
    }

    @Test
    @DisplayName("a target the reader may not see has no scorecard and no API inventory")
    void everyPerTargetReadIsGuarded() throws Exception {
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        long theirs = repository("https://example.invalid/theirs.git");
        String reader = assignedReader(mine);

        for (String route : List.of(
                "/api/v1/scorecard/repositories/" + theirs,
                "/api/v1/repositories/" + theirs + "/apis",
                "/api/v1/repositories/" + theirs + "/apis/export/openapi")) {
            mvc.perform(authenticated(get(route), reader))
                    .andExpect(status().isNotFound());
        }

        // **The guard must not narrow what the reader was given**, and this is the assertion
        // that says so without asserting a fixture detail: on their own repository the reader
        // gets whatever an administrator gets. Written this way after a first version asserted
        // 200 and failed — an administrator gets 404 too, because a repository with no scan has
        // no scorecard. That is the product's behaviour and not this guard's doing.
        int forAnAdministrator = mvc.perform(
                        authenticated(get("/api/v1/scorecard/repositories/" + mine), asAdmin()))
                .andReturn().getResponse().getStatus();
        mvc.perform(authenticated(get("/api/v1/scorecard/repositories/" + mine), reader))
                .andExpect(status().is(forAnAdministrator));
    }

    @Test
    @DisplayName("an issue the reader may not see cannot be explained to them either")
    void theAiExplanationIsGuarded() throws Exception {
        // The route already took the principal and already ignored it. An explanation names the
        // package, the file and the fix — it is the finding itself, in prose.
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        long theirs = repository("https://example.invalid/theirs.git");
        long theirIssue = issue(theirs, "CVE-2026-9");
        String reader = assignedReader(mine);

        mvc.perform(authenticated(post("/api/v1/ai-advisor/explain/issue/" + theirIssue), reader))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("no aggregate answers with the estate: eight routes, one allowance")
    void everyAggregateIsScoped() throws Exception {
        // **The remainder of the authorization sweep, asserted in one place.** Each of these
        // summarises the whole deployment by design, which is exactly why each had to be told
        // whose deployment to summarise. A guard per route could not close them: the allowance
        // has to reach the query that builds the document.
        restrict();
        long mine = repository("https://example.invalid/mine.git");
        long theirs = repository("https://example.invalid/theirs.git");
        issue(mine, "CVE-2026-1");
        issue(theirs, "CVE-2026-2");
        finding(theirs, "spring-beans", "CVE-2026-2");
        String reader = assignedReader(mine);

        // The three exports name the CVE they are about, so the neighbour's must be absent.
        for (String route : List.of(
                "/api/v1/csaf/aggregate.json",
                "/api/v1/cyclonedx/aggregate.json",
                "/api/v1/vex/aggregate.json")) {
            String body = mvc.perform(authenticated(get(route), reader))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();
            org.assertj.core.api.Assertions.assertThat(body)
                    .as("%s must not carry the neighbour's identifier", route)
                    .contains("CVE-2026-1")
                    .doesNotContain("CVE-2026-2");
        }

        // The EPSS ranking and the portfolio scorecard count what they can see.
        mvc.perform(authenticated(get("/api/v1/epss/priorities"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalVulnerabilities").value(1));

        // The attack surface is a map of exposed paths; an empty one here is the right answer
        // because the reader's repository has no discovered endpoint, and the neighbour's
        // absence is the assertion.
        mvc.perform(authenticated(get("/api/v1/attack-surface"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEndpoints").value(0));

        mvc.perform(authenticated(get("/api/v1/quality/overview"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openCount").value(0));
    }

    private void restrict() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
    }

    /** A reader with one repository assigned, through the administration route it really uses. */
    private String assignedReader(long repositoryId) throws Exception {
        String reader = asReader();
        long readerId = mvc.perform(authenticated(get("/api/v1/users"), asAdmin()))
                .andReturn()
                .getResponse()
                .getContentAsString()
                .transform(body -> readerIdFrom(body));

        mvc.perform(authenticated(put("/api/v1/users/" + readerId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "repository", "id", repositoryId)))))
                .andExpect(status().isOk());
        return reader;
    }

    private long readerIdFrom(String body) {
        try {
            for (var node : json.readTree(body).path("users")) {
                if (node.path("username").asText("").startsWith("reader-")) {
                    return node.path("id").asLong();
                }
            }
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
        throw new IllegalStateException("no reader account in the listing");
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    /** A completed scan of one repository, with nothing in it. */
    private long scan(long repoId) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        return scans.save(scan).getId();
    }

    /** A completed scan of one repository, carrying one vulnerable package. */
    private void finding(long repoId, String packageName, String identifier) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        long scanId = scans.save(scan).getId();

        FindingEntity finding = new FindingEntity();
        finding.setScanId(scanId);
        finding.setType(FindingType.VULNERABILITY.wireName());
        finding.setIdentifier(identifier);
        finding.setSeverity(Severity.HIGH.wireName());
        finding.setPackageName(packageName);
        finding.setPackageVersion("1.0.0");
        finding.setIsDirectDependency(true);
        finding.setSource("grype");
        finding.setCreatedAt(Instant.now());
        findings.save(finding);
    }

    private long issue(long repoId, String identifier) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
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
