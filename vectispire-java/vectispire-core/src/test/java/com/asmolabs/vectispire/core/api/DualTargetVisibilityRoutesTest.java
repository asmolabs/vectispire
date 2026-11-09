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
import com.asmolabs.vectispire.common.domain.paging.RegisterCursor;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * A row naming both a repository and an image, read by a reader granted only the image.
 *
 * <p><b>Such a row is its repository's</b> — {@code target()} on the scan, the issue and the verdict, which
 * {@code Visibility.permits} is asked of, and the rule the scan history applies. Four reads matched either
 * column instead: the gate verdict register and the exceptions register (their second lock dropped the row,
 * but the cursor is taken from the rows read and named it), the backlog and every figure built on its
 * predicate, and the blast radius's packages. The dashboard's recent scans did too, and now read through the
 * history's own statement — {@code RecentScansVisibilityRoutesTest} holds them. Each is asked here through its
 * route: the reader granted the image alone sees nothing of the row — not in the rows, the counts, nor in
 * any cursor of a walk one row at a time — a reader granted both sees it once, an administrator sees it.
 *
 * <p>No writer of this tree sets both columns: the gate, the scheduler, the triggers and the issue sync each
 * write one, from a {@code ScanTarget} (the sync's first version copied both of its scan's). The rows are
 * therefore written as a restore would write them. Dated in 2090 so that they are the newest of whatever
 * this context's other tests left, and the pages of one row reach them first.
 */
@DisplayName("a row naming both a repository and an image")
class DualTargetVisibilityRoutesTest extends ApiTestBase {

    private static final Instant FUTURE = Instant.parse("2090-01-01T00:00:00Z");

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private FindingRepository findings;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private GateVerdictRepository verdicts;

    @Autowired
    private UserRepository users;

    @Autowired
    private SettingsService settings;

    private String hiddenName;
    private long hidden;
    private long image;

    @BeforeEach
    void targets() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        hiddenName = "dual-hidden-" + System.nanoTime();
        hidden = repository(hiddenName);
        image = container("dual-image");
    }

    @AfterEach
    void everyoneAgain() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());
    }

    @Nested
    @DisplayName("in the gate verdict register")
    class GateRegister {

        @Test
        @DisplayName("is not read for a reader of the image: not listed, not counted, never a cursor")
        void hiddenFromAReaderOfTheImage() throws Exception {
            UUID imageOnly = verdict(null, image, FUTURE.plusSeconds(100));
            UUID both = verdict(hidden, image, FUTURE.plusSeconds(101));
            UUID newer = verdict(null, image, FUTURE.plusSeconds(102));
            UUID newest = verdict(hidden, image, FUTURE.plusSeconds(103));
            String reader = readerGranted(image(image));

            // One row a page: read by either column, the first page read the dual verdict, dropped it, and
            // handed back a cursor naming it. A dual verdict at the head and another between two of the
            // image's, so that both statements — the first page's and the next's — are asked about one.
            List<JsonNode> pages = walk("/api/v1/gate/verdicts", "verdicts", reader);
            assertThat(idsOf(pages, "verdicts", row -> row.path("id").asText()))
                    .containsExactly(newer.toString(), imageOnly.toString());
            assertThat(cursorIds(pages)).doesNotContain(both.toString(), newest.toString());
            assertThat(pages.stream().mapToLong(page -> page.path("passed").asLong() + page.path("refused").asLong()).sum())
                    .isEqualTo(2);
            assertThat(pages.toString()).doesNotContain(hiddenName);
        }

        @Test
        @DisplayName("is read once by a reader of both, and by an administrator")
        void shownToAReaderOfBoth() throws Exception {
            UUID imageOnly = verdict(null, image, FUTURE.plusSeconds(110));
            UUID both = verdict(hidden, image, FUTURE.plusSeconds(111));
            String reader = readerGranted(repository(hidden), image(image));

            assertThat(idsOf(walk("/api/v1/gate/verdicts", "verdicts", reader), "verdicts", row -> row.path("id").asText()))
                    .containsExactly(both.toString(), imageOnly.toString());
            JsonNode all = read(get("/api/v1/gate/verdicts"), asAdmin());
            assertThat(StreamSupport.stream(all.path("verdicts").spliterator(), false).map(row -> row.path("id").asText()))
                    .contains(both.toString(), imageOnly.toString());
        }
    }

    @Nested
    @DisplayName("in the exceptions register")
    class ExceptionsRegister {

        @Test
        @DisplayName("is not read for a reader of the image: not listed, not counted, never a cursor")
        void hiddenFromAReaderOfTheImage() throws Exception {
            long imageOnly = issue(null, image, "CVE-DUAL-EXC-IMG", TriageStatus.NOT_AFFECTED, FUTURE.plusSeconds(200));
            long both = issue(hidden, image, "CVE-DUAL-EXC-BOTH", TriageStatus.NOT_AFFECTED, FUTURE.plusSeconds(201));
            long newer = issue(null, image, "CVE-DUAL-EXC-NEW", TriageStatus.NOT_AFFECTED, FUTURE.plusSeconds(202));
            long newest = issue(hidden, image, "CVE-DUAL-EXC-HEAD", TriageStatus.NOT_AFFECTED, FUTURE.plusSeconds(203));
            String reader = readerGranted(image(image));

            // A dual exception at the head and another between two of the image's, so that both statements,
            // the first page's and the next's, are asked about one.
            List<JsonNode> pages = walk("/api/v1/exceptions", "entries", reader);
            assertThat(idsOf(pages, "entries", row -> row.path("issue_id").asText()))
                    .containsExactly(String.valueOf(newer), String.valueOf(imageOnly));
            assertThat(cursorIds(pages)).doesNotContain(String.valueOf(both), String.valueOf(newest));
            assertThat(pages.stream().mapToLong(page -> page.path("granted").asLong()).sum()).isEqualTo(2);
            assertThat(pages.toString()).doesNotContain(hiddenName);
        }

        @Test
        @DisplayName("is read once by a reader of both, and by an administrator")
        void shownToAReaderOfBoth() throws Exception {
            long imageOnly = issue(null, image, "CVE-DUAL-EXC-IMG", TriageStatus.NOT_AFFECTED, FUTURE.plusSeconds(210));
            long both = issue(hidden, image, "CVE-DUAL-EXC-BOTH", TriageStatus.NOT_AFFECTED, FUTURE.plusSeconds(211));
            String reader = readerGranted(repository(hidden), image(image));

            assertThat(idsOf(walk("/api/v1/exceptions", "entries", reader), "entries", row -> row.path("issue_id").asText()))
                    .containsExactly(String.valueOf(both), String.valueOf(imageOnly));
            JsonNode all = read(get("/api/v1/exceptions").param("limit", "500"), asAdmin());
            assertThat(StreamSupport.stream(all.path("entries").spliterator(), false).map(row -> row.path("issue_id").asLong()))
                    .contains(both, imageOnly);
        }
    }

    @Nested
    @DisplayName("in the backlog")
    class Backlog {

        @Test
        @DisplayName("is not read for a reader of the image: not listed, not counted, on no page, nor through the image's filter")
        void hiddenFromAReaderOfTheImage() throws Exception {
            String search = "cve-dual-backlog-" + System.nanoTime();
            long imageOnly = issue(null, image, search + "-img", null, null);
            long both = issue(hidden, image, search + "-both", null, null);
            String reader = readerGranted(image(image));

            JsonNode first = read(backlog(search).param("limit", "1"), reader);
            assertThat(first.path("total").asLong()).isEqualTo(1);
            assertThat(backlogIds(reader, search)).containsExactly(imageOnly);
            JsonNode filtered = read(backlog(search).param("container_id", String.valueOf(image)), reader);
            assertThat(filtered.path("total").asLong()).isEqualTo(1);
            assertThat(idsOf(List.of(filtered), "items", row -> row.path("id").asText()))
                    .containsExactly(String.valueOf(imageOnly))
                    .doesNotContain(String.valueOf(both));
            assertThat(filtered.toString()).doesNotContain(hiddenName);
            // The exact-identifier filter, the links' "this CVE", reads the same predicate.
            JsonNode exact = read(get("/api/v1/issues").param("identifier", search + "-both"), reader);
            assertThat(exact.path("total").asLong()).isZero();
            assertThat(exact.path("items")).isEmpty();
        }

        @Test
        @DisplayName("is read once by a reader of both, and by an administrator")
        void shownToAReaderOfBoth() throws Exception {
            String search = "cve-dual-backlog-" + System.nanoTime();
            long imageOnly = issue(null, image, search + "-img", null, null);
            long both = issue(hidden, image, search + "-both", null, null);
            String reader = readerGranted(repository(hidden), image(image));

            assertThat(read(backlog(search), reader).path("total").asLong()).isEqualTo(2);
            assertThat(backlogIds(reader, search)).containsExactlyInAnyOrder(both, imageOnly);
            assertThat(read(backlog(search), asAdmin()).path("total").asLong()).isEqualTo(2);
        }

        private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder backlog(String search) {
            return get("/api/v1/issues").param("search", search);
        }

        /** Every page of one row, offset by offset. */
        private List<Long> backlogIds(String reader, String search) throws Exception {
            List<Long> ids = new ArrayList<>();
            for (int offset = 0; offset < 5; offset++) {
                JsonNode page = read(backlog(search).param("limit", "1").param("offset", String.valueOf(offset)), reader);
                page.path("items").forEach(row -> ids.add(row.path("id").asLong()));
            }
            return ids;
        }
    }

    @Nested
    @DisplayName("in the blast radius")
    class BlastRadius {

        @Test
        @DisplayName("does not count its packages for a reader of the image, nor name its repository")
        void hiddenFromAReaderOfTheImage() throws Exception {
            String pkg = "dual-pkg-" + System.nanoTime();
            finding(scan(hidden, image, FUTURE.plusSeconds(400)), pkg);
            String reader = readerGranted(image(image));

            JsonNode explored = read(get("/api/v1/blast-radius/explore").param("q", pkg), reader);
            assertThat(explored.path("totalTargetsAffected").asInt()).isZero();
            assertThat(explored.toString()).doesNotContain(hiddenName);
            assertThat(topImpact(reader, pkg)).isNull();
        }

        @Test
        @DisplayName("counts it as its repository's, one target, for a reader of both and an administrator")
        void oneTargetForAReaderOfBoth() throws Exception {
            String pkg = "dual-pkg-" + System.nanoTime();
            finding(scan(hidden, image, FUTURE.plusSeconds(410)), pkg);
            String reader = readerGranted(repository(hidden), image(image));

            for (String caller : List.of(reader, asAdmin())) {
                JsonNode explored = read(get("/api/v1/blast-radius/explore").param("q", pkg), caller);
                assertThat(explored.path("totalTargetsAffected").asInt()).isEqualTo(1);
                assertThat(explored.path("targets").get(0).path("targetKind").asText()).isEqualTo("REPOSITORY");
                // The landing list said two — the repository and the image — where the explorer said one.
                assertThat(topImpact(caller, pkg)).isNotNull();
                assertThat(topImpact(caller, pkg).path("affectedTargetsCount").asInt()).isEqualTo(1);
            }
        }

        private JsonNode topImpact(String caller, String pkg) throws Exception {
            for (JsonNode row : read(get("/api/v1/blast-radius/top-impact").param("limit", "100000"), caller)) {
                if (pkg.equals(row.path("packageName").asText())) {
                    return row;
                }
            }
            return null;
        }
    }

    /** Every page of a register read one row at a time, following its cursor. */
    private List<JsonNode> walk(String route, String rows, String reader) throws Exception {
        List<JsonNode> pages = new ArrayList<>();
        String cursor = null;
        do {
            var request = get(route).param("limit", "1");
            if (cursor != null) {
                request.param("cursor", cursor);
            }
            JsonNode page = read(request, reader);
            pages.add(page);
            cursor = page.path("next_cursor").isTextual() ? page.path("next_cursor").asText() : null;
        } while (cursor != null && pages.size() < 10);
        assertThat(cursor).as("the walk reached the end of " + route).isNull();
        return pages;
    }

    private static List<String> cursorIds(List<JsonNode> pages) {
        return pages.stream()
                .map(page -> page.path("next_cursor"))
                .filter(JsonNode::isTextual)
                .map(cursor -> RegisterCursor.parse(cursor.asText()).orElseThrow().id())
                .toList();
    }

    private static List<String> idsOf(List<JsonNode> pages, String rows, Function<JsonNode, String> id) {
        return pages.stream()
                .flatMap(page -> StreamSupport.stream((rows == null ? page : page.path(rows)).spliterator(), false))
                .map(id)
                .toList();
    }

    private JsonNode read(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request, String token)
            throws Exception {
        return json.readTree(mvc.perform(authenticated(request, token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private static Map<String, Object> repository(long id) {
        return Map.of("kind", "repository", "id", id);
    }

    private static Map<String, Object> image(long id) {
        return Map.of("kind", "container", "id", id);
    }

    /** A reader granted these targets, through the administration route it really uses. */
    private String readerGranted(Map<String, Object> first, Map<?, ?>... more) throws Exception {
        List<Object> targets = new ArrayList<>(List.of(first));
        targets.addAll(List.of(more));
        String name = "dual-reader-" + System.nanoTime();
        String reader = tokenFor(name, Role.USER, false);
        long id = users.findByUsername(name).orElseThrow().getId();
        mvc.perform(authenticated(put("/api/v1/users/" + id + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(targets)))
                .andExpect(status().isOk());
        return reader;
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setName(name);
        repository.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container(String name) {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("registry.example.invalid/" + name + "-" + System.nanoTime());
        container.setTag("1.0.0");
        return containers.save(container).getId();
    }

    private long scan(Long repoId, Long containerId, Instant createdAt) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setContainerId(containerId);
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(createdAt);
        return scans.save(scan).getId();
    }

    private void finding(long scanId, String packageName) {
        FindingEntity finding = new FindingEntity();
        finding.setScanId(scanId);
        finding.setType("sca");
        finding.setIdentifier("CVE-2090-0001");
        finding.setPackageName(packageName);
        finding.setPackageVersion("1.0");
        finding.setPurl("pkg:maven/example/" + packageName + "@1.0");
        finding.setSource("trivy");
        finding.setSeverity("HIGH");
        finding.setCvssScore(9.8);
        finding.setIsDirectDependency(true);
        finding.setCreatedAt(Instant.now());
        findings.save(finding);
    }

    /** An open issue under review, or carrying {@code triage} decided at {@code at} when one is given. */
    private long issue(Long repoId, Long containerId, String identifier, TriageStatus triage, Instant at) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setContainerId(containerId);
        issue.setFingerprint(identifier + "-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        if (triage != null) {
            issue.setTriageStatus(triage.wireName());
            issue.setTriageJustification("vulnerable_code_not_present");
            issue.setTriagedAt(at);
            issue.setTriagedBy("admin");
        }
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }

    /** A refusal recorded on these columns, as a restore would write it. */
    private UUID verdict(Long repoId, Long containerId, Instant at) {
        GateVerdictEntity row = new GateVerdictEntity();
        row.setId(UUID.randomUUID());
        row.setRepoId(repoId);
        row.setContainerId(containerId);
        row.setPassed(false);
        row.setEvaluated(3);
        row.setViolations(1);
        row.setCriticalCount(1);
        row.setPolicySource("GLOBAL");
        row.setDecidedAt(at);
        row.setDecidedBy("restored");
        return verdicts.save(row).getId();
    }
}
