package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.scanning.ScanQueryService;
import com.asmolabs.vectispire.core.scanning.ScanView;
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
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.LongStream;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The reads that page on request since the second lot of 0.11.1: the triage history's repositories, the
 * attack-path overview, the licence inventory and its conflicts, and the scan history's {@code offset}.
 *
 * <p>The same contract as {@link ListPagingRoutesTest}'s: asked nothing, each answers what it answered — the
 * same array — and asked a page, the array cut from what the caller sees, the visibility applied before the
 * cut, a page it cannot serve refused with a 400 that says why.
 */
@DisplayName("the reads that page on request")
class ListPagingReadsRoutesTest extends ApiTestBase {

    private static final Instant START = Instant.parse("2026-10-01T00:00:00Z");

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ScanQueryService scanQueries;

    @Autowired
    private UserRepository users;

    @Autowired
    private SettingsService settings;

    // --- the triage history's repositories ------------------------------------------------------------

    @Test
    @DisplayName("history: most recently scanned first, never-scanned last by id; the pages are that list cut")
    void historyPages() throws Exception {
        long oldest = repository("hist-oldest");
        long newest = repository("hist-newest");
        long never = repository("hist-never");
        long middle = repository("hist-middle");
        long neverToo = repository("hist-never-too");
        scan(oldest, null, START);
        scan(newest, null, START.plusSeconds(30));
        // Created later with an earlier instant: the order is the instant's, not the identifier's.
        scan(middle, null, START.plusSeconds(20));
        scan(middle, null, START.plusSeconds(10));
        String admin = asAdmin();
        String route = "/api/v1/history/repositories";

        List<Long> every = ids(read(route, admin));
        assertThat(every).containsExactly(newest, middle, oldest, never, neverToo);
        assertThat(paged(route, admin, 2)).containsExactlyElementsOf(every);
        assertThat(ids(read(route + "?limit=2&offset=2", admin))).containsExactly(oldest, never);
        // The row a page builds is the row the whole list builds.
        assertThat(read(route + "?limit=2", admin).get(1)).isEqualTo(read(route, admin).get(1));
    }

    @Test
    @DisplayName("history: a restricted reader's pages are cut from what they see")
    void historyPagesKeepTheVisibility() throws Exception {
        List<Long> filed = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            filed.add(repository("hist-restricted-" + i));
            scan(filed.getLast(), null, START.plusSeconds(i));
        }
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String readerName = "pager-" + System.nanoTime();
        String reader = tokenFor(readerName, Role.USER, false);
        grant(idOf(readerName), List.of(filed.get(0), filed.get(2), filed.get(3)));

        String route = "/api/v1/history/repositories";
        // Newest first among the reader's own: counted over the estate, the second page would have started
        // at the estate's third row and come back short.
        assertThat(ids(read(route + "?limit=2", reader))).containsExactly(filed.get(3), filed.get(2));
        assertThat(ids(read(route + "?limit=2&offset=2", reader))).containsExactly(filed.get(0));
        assertThat(ids(read(route, reader))).containsExactly(filed.get(3), filed.get(2), filed.get(0));
    }

    // --- the attack-path overview ---------------------------------------------------------------------

    @Test
    @DisplayName("attack paths: by repository id; the pages are that list cut, a restricted reader's from theirs")
    void attackPathOverviewPages() throws Exception {
        List<Long> filed = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            filed.add(repository("paths-" + i));
        }
        String admin = asAdmin();
        String route = "/api/v1/attack-paths/overview";

        List<Long> every = targetIds(read(route, admin));
        assertThat(every).containsExactlyElementsOf(filed);
        assertThat(pagedBy(route, admin, 2, ListPagingReadsRoutesTest::targetIds)).containsExactlyElementsOf(every);
        assertThat(targetIds(read(route + "?limit=2&offset=4", admin))).containsExactly(filed.get(4));

        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String readerName = "pager-" + System.nanoTime();
        String reader = tokenFor(readerName, Role.USER, false);
        grant(idOf(readerName), List.of(filed.get(1), filed.get(3), filed.get(4)));
        assertThat(targetIds(read(route + "?limit=2", reader))).containsExactly(filed.get(1), filed.get(3));
        assertThat(targetIds(read(route + "?limit=2&offset=2", reader))).containsExactly(filed.get(4));
    }

    // --- the licence inventory and its conflicts ------------------------------------------------------

    @Test
    @DisplayName("licences: asked nothing, the inventory as before; asked pages, that inventory by target, package, version")
    void licenceInventoryPages() throws Exception {
        long first = repository("lic-a");
        long second = repository("lic-b");
        scanWithSbom(first, "zeta", "alpha", "mid");
        scanWithSbom(second, "beta", "omega");
        String admin = asAdmin();
        String route = "/api/v1/licenses/inventory";

        List<JsonNode> every = rows(read(route, admin));
        assertThat(every).hasSize(5);
        List<JsonNode> paged = new ArrayList<>();
        for (int offset = 0; offset < every.size() + 2; offset += 2) {
            JsonNode page = read(route + "?limit=2&offset=" + offset, admin);
            assertThat(page.size()).as("page at " + offset).isLessThanOrEqualTo(2);
            page.forEach(paged::add);
        }
        // The same entries, whole; in the page order, which the unpaged answer — a hash map's — does not promise.
        assertThat(paged).containsExactlyInAnyOrderElementsOf(every);
        assertThat(paged.stream().map(entry -> entry.path("targetId").asLong() + "/" + entry.path("packageName").asText()))
                .containsExactly(first + "/alpha", first + "/mid", first + "/zeta", second + "/beta", second + "/omega");
        assertThat(paged).isEqualTo(paged.stream().sorted(Comparator
                .comparing((JsonNode entry) -> entry.path("targetId").asLong())
                .thenComparing(entry -> entry.path("packageName").asText())).toList());

        // A named target pages within it.
        assertThat(rows(read(route + "?repo_id=" + second + "&limit=1&offset=1", admin)))
                .extracting(entry -> entry.path("packageName").asText()).containsExactly("omega");
    }

    @Test
    @DisplayName("licences: a restricted reader's pages hold their targets' entries only")
    void licencePagesKeepTheVisibility() throws Exception {
        long mine = repository("lic-mine");
        long theirs = repository("lic-theirs");
        scanWithSbom(mine, "one", "two", "three");
        scanWithSbom(theirs, "hidden-a", "hidden-b");
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String readerName = "pager-" + System.nanoTime();
        String reader = tokenFor(readerName, Role.USER, false);
        grant(idOf(readerName), List.of(mine));

        String route = "/api/v1/licenses/inventory";
        assertThat(rows(read(route + "?limit=2", reader))).extracting(entry -> entry.path("packageName").asText())
                .containsExactly("one", "three");
        assertThat(rows(read(route + "?limit=2&offset=2", reader))).extracting(entry -> entry.path("packageName").asText())
                .containsExactly("two");
        assertThat(rows(read(route, reader))).allSatisfy(entry -> assertThat(entry.path("targetId").asLong()).isEqualTo(mine));
    }

    @Test
    @DisplayName("licence conflicts: the pages are every conflict; a restricted reader naming no target is a 404 first")
    void licenceConflictsPage() throws Exception {
        long first = repository("conf-a");
        long second = repository("conf-b");
        scanWithSbom(first, "gpl-z", "gpl-a");
        scanWithSbom(second, "gpl-m");
        String admin = asAdmin();
        String route = "/api/v1/licenses/conflicts";

        List<JsonNode> every = rows(read(route, admin));
        assertThat(every).hasSize(3);
        List<JsonNode> paged = new ArrayList<>();
        for (int offset = 0; offset < every.size() + 2; offset += 2) {
            read(route + "?limit=2&offset=" + offset, admin).forEach(paged::add);
        }
        assertThat(paged).containsExactlyInAnyOrderElementsOf(every);
        assertThat(paged).extracting(conflict -> conflict.path("packageName").asText())
                .containsExactly("gpl-a", "gpl-z", "gpl-m");

        // The estate's conflicts are refused a restricted reader before the window is read: the parameters'
        // 400 would answer for an aggregate they are told is not there.
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String reader = tokenFor("pager-" + System.nanoTime(), Role.USER, false);
        mvc.perform(authenticated(get(route + "?limit=9999"), reader)).andExpect(status().isNotFound());
    }

    // --- the scan history's offset ---------------------------------------------------------------------

    @Test
    @DisplayName("scans: asked nothing, the latest fifty; with an offset, the pages of that history cut in order")
    void scanHistoryPages() throws Exception {
        long repository = repository("scans-paged");
        List<Long> newestFirst = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            newestFirst.addFirst(scan(repository, null, START.plusSeconds(i)));
        }
        String admin = asAdmin();

        assertThat(ids(read("/api/v1/scans", admin))).containsExactlyElementsOf(newestFirst);
        assertThat(ids(read("/api/v1/scans?limit=3&offset=0", admin))).containsExactlyElementsOf(newestFirst.subList(0, 3));
        assertThat(ids(read("/api/v1/scans?limit=3&offset=3", admin))).containsExactlyElementsOf(newestFirst.subList(3, 6));
        assertThat(ids(read("/api/v1/scans?limit=3&offset=6&repo_id=" + repository, admin)))
                .containsExactly(newestFirst.get(6));
        assertThat(ids(read("/api/v1/scans?limit=3&offset=9", admin))).isEmpty();
    }

    @Test
    @DisplayName("scans: a restricted reader's history is their own, read in the query, never a share of the estate's")
    void scanHistoryKeepsTheVisibility() throws Exception {
        long mine = repository("scans-mine");
        long hidden = repository("scans-hidden");
        long image = container("scans-image");
        long ownOldest = scan(mine, null, START);
        long ownImage = scan(null, image, START.plusSeconds(1));
        // An image scan that names a hidden repository is the repository's, and stays hidden.
        scan(hidden, image, START.plusSeconds(2));
        long ownNewest = scan(mine, null, START.plusSeconds(3));
        for (int i = 0; i < 4; i++) {
            scan(hidden, null, START.plusSeconds(10 + i));
        }
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String readerName = "pager-" + System.nanoTime();
        String reader = tokenFor(readerName, Role.USER, false);
        mvc.perform(authenticated(put("/api/v1/users/" + idOf(readerName) + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(
                                Map.of("kind", "repository", "id", mine), Map.of("kind", "container", "id", image)))))
                .andExpect(status().isOk());

        // The estate's two latest are the hidden repository's: filtered after the cap, this read came back empty.
        assertThat(ids(read("/api/v1/scans?limit=2", reader))).containsExactly(ownNewest, ownImage);
        assertThat(ids(read("/api/v1/scans?limit=2&offset=2", reader))).containsExactly(ownOldest);
        assertThat(ids(read("/api/v1/scans", reader))).containsExactly(ownNewest, ownImage, ownOldest);
        assertThat(ids(read("/api/v1/scans?container_id=" + image, reader))).containsExactly(ownImage);
        assertThat(ids(read("/api/v1/scans?repo_id=" + hidden, reader))).isEmpty();
    }

    @Test
    @DisplayName("scans: an allowance past one statement's thousand identifiers pages as one that fits")
    void scanHistoryPagesAcrossBatches() {
        List<Long> real = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            real.add(repository("scans-batch-" + i));
        }
        List<Long> newestFirst = new ArrayList<>();
        for (int i = 0; i < 9; i++) {
            newestFirst.addFirst(scan(real.get(i % 3), null, START.plusSeconds(i)));
        }
        // 999 identifiers no row has, sorted before the real ones: the first statement holds the first real
        // repository, the second the other two, and a page is cut from both.
        Visibility wide = Visibility.only(Stream.concat(
                        LongStream.rangeClosed(1, 999).mapToObj(id -> new ScanTarget.Repository(-id)),
                        real.stream().map(ScanTarget.Repository::new))
                .map(ScanTarget.class::cast).toList());
        Visibility narrow = Visibility.only(real.stream().map(id -> (ScanTarget) new ScanTarget.Repository(id)).toList());

        for (int offset = 0; offset <= 9; offset += 2) {
            assertThat(scanIds(wide, 2, offset)).as("at " + offset).isEqualTo(scanIds(narrow, 2, offset));
        }
        assertThat(scanIds(wide, 2, 2)).containsExactlyElementsOf(newestFirst.subList(2, 4));
        assertThat(scanIds(wide, 4, 8)).containsExactly(newestFirst.get(8));
    }

    /**
     * A reader seeing more than a thousand targets is served in several statements, each reading its batch's newest
     * {@code offset + limit} whole and merged in the JVM: past ten thousand deep, a page is refused rather than the
     * history of every batch held for it. One statement — a narrower reader, or the whole estate — pages in the
     * database and goes as deep as asked.
     */
    @Test
    @DisplayName("scans: a history read in several statements reaches ten thousand deep, and refuses deeper in words")
    void scanHistoryAcrossBatchesHasADepth() throws Exception {
        List<RepositoryEntity> filed = new ArrayList<>();
        for (int i = 0; i < 1_001; i++) {
            RepositoryEntity repository = new RepositoryEntity();
            repository.setName("scans-deep-" + i);
            repository.setUrl("https://example.invalid/scans-deep-" + i + "-" + System.nanoTime() + ".git");
            repository.setBranch("main");
            filed.add(repository);
        }
        List<Long> granted = repositories.saveAll(filed).stream().map(RepositoryEntity::getId).toList();
        scan(granted.getLast(), null, START);
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String wideName = "pager-wide-" + System.nanoTime();
        String wide = tokenFor(wideName, Role.USER, false);
        grant(idOf(wideName), granted);
        String narrowName = "pager-narrow-" + System.nanoTime();
        String narrow = tokenFor(narrowName, Role.USER, false);
        grant(idOf(narrowName), List.of(granted.getLast()));

        assertThat(ids(read("/api/v1/scans?limit=200", wide))).hasSize(1);
        assertThat(read("/api/v1/scans?limit=200&offset=9800", wide)).as("ten thousand deep, exactly").isEmpty();
        assertThat(refusal("/api/v1/scans?limit=200&offset=10000", wide)).isEqualTo(
                "For a reader of more than 1000 targets, the history reaches 10000 scans deep: offset plus limit is "
                        + "10000 at most.");
        assertThat(refusal("/api/v1/scans?limit=1&offset=10000", wide)).contains("offset plus limit is 10000 at most");

        assertThat(read("/api/v1/scans?limit=200&offset=10000", narrow)).as("one statement").isEmpty();
        assertThat(read("/api/v1/scans?limit=200&offset=10000", asAdmin())).as("the estate").isEmpty();
    }

    // --- the refusals -----------------------------------------------------------------------------------

    @Test
    @DisplayName("refuses a page it cannot serve with a 400 that says why, on every route")
    void refusesWhatItCannotServe() throws Exception {
        String admin = asAdmin();
        for (String route : List.of("/api/v1/history/repositories", "/api/v1/attack-paths/overview",
                "/api/v1/licenses/inventory", "/api/v1/licenses/conflicts")) {
            assertThat(refusal(route + "?limit=501", admin)).as(route).isEqualTo("The limit is between 1 and 500.");
            assertThat(refusal(route + "?limit=0", admin)).as(route).isEqualTo("The limit is between 1 and 500.");
            assertThat(refusal(route + "?limit=-1", admin)).as(route).isEqualTo("The limit is between 1 and 500.");
            assertThat(refusal(route + "?limit=10&offset=5", admin)).as(route)
                    .isEqualTo("The offset is zero or a multiple of the limit.");
            assertThat(refusal(route + "?limit=10&offset=-10", admin)).as(route)
                    .isEqualTo("The offset is zero or a multiple of the limit.");
            assertThat(refusal(route + "?offset=10", admin)).as(route).contains("with a limit");
            mvc.perform(authenticated(get(route + "?limit=500"), admin)).andExpect(status().isOk());
        }

        // The scan history's limit has been brought within 1 to 200 since before paging, and still is: a
        // client sending 1000 is answered as it was. Only the offset is refused, against the limit as read.
        mvc.perform(authenticated(get("/api/v1/scans?limit=0"), admin)).andExpect(status().isOk());
        mvc.perform(authenticated(get("/api/v1/scans?limit=1000"), admin)).andExpect(status().isOk());
        assertThat(refusal("/api/v1/scans?offset=-50", admin)).isEqualTo("The offset is zero or a multiple of the limit.");
        assertThat(refusal("/api/v1/scans?limit=10&offset=5", admin))
                .isEqualTo("The offset is zero or a multiple of the limit.");
        assertThat(refusal("/api/v1/scans?limit=1000&offset=500", admin))
                .isEqualTo("The offset is zero or a multiple of the limit.");
        mvc.perform(authenticated(get("/api/v1/scans?limit=1000&offset=400"), admin)).andExpect(status().isOk());
        mvc.perform(authenticated(get("/api/v1/scans?offset=50"), admin)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("a named target the caller cannot see is the 404 an absent one is, whatever the window")
    void aHiddenTargetIsRefusedBeforeTheWindow() throws Exception {
        long hidden = repository("lic-hidden");
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String reader = tokenFor("pager-" + System.nanoTime(), Role.USER, false);
        for (String route : List.of("/api/v1/licenses/inventory", "/api/v1/licenses/conflicts")) {
            MvcResult seen = mvc.perform(authenticated(get(route + "?repo_id=" + hidden + "&limit=9999"), reader))
                    .andExpect(status().isNotFound()).andReturn();
            MvcResult absent = mvc.perform(authenticated(get(route + "?repo_id=987654321&limit=9999"), reader))
                    .andExpect(status().isNotFound()).andReturn();
            assertThat(detailOf(seen)).as(route).isEqualTo(detailOf(absent));
        }
    }

    // --- helpers ------------------------------------------------------------------------------------------

    private List<Long> scanIds(Visibility allowed, int limit, int offset) {
        return scanQueries.history(allowed, null, null, limit, offset).scans().stream().map(ScanView::id).toList();
    }

    private List<Long> paged(String route, String token, int limit) throws Exception {
        return pagedBy(route, token, limit, ListPagingReadsRoutesTest::ids);
    }

    private List<Long> pagedBy(String route, String token, int limit, Function<JsonNode, List<Long>> idsOf)
            throws Exception {
        List<Long> paged = new ArrayList<>();
        for (int offset = 0; ; offset += limit) {
            List<Long> page = idsOf.apply(read(route + "?limit=" + limit + "&offset=" + offset, token));
            assertThat(page.size()).isLessThanOrEqualTo(limit);
            paged.addAll(page);
            if (page.size() < limit) {
                return paged;
            }
        }
    }

    private String refusal(String route, String token) throws Exception {
        return detailOf(mvc.perform(authenticated(get(route), token)).andExpect(status().isBadRequest()).andReturn());
    }

    private JsonNode read(String route, String token) throws Exception {
        JsonNode body = json.readTree(mvc.perform(authenticated(get(route), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        assertThat(body.isArray()).as(route + " still an array").isTrue();
        return body;
    }

    private static List<JsonNode> rows(JsonNode array) {
        return StreamSupport.stream(array.spliterator(), false).toList();
    }

    private static List<Long> ids(JsonNode array) {
        return rows(array).stream().map(node -> node.path("id").asLong()).toList();
    }

    private static List<Long> targetIds(JsonNode array) {
        return rows(array).stream().map(node -> node.path("targetId").asLong()).toList();
    }

    private long idOf(String username) {
        return users.findByUsername(username).orElseThrow().getId();
    }

    private void grant(long accountId, List<Long> repositoryIds) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + accountId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(repositoryIds.stream()
                                .map(id -> Map.of("kind", "repository", "id", id))
                                .toList())))
                .andExpect(status().isOk());
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
        container.setImageName("registry.example.invalid/" + name);
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

    /** A scan whose SBOM declares each package under GPL-2.0, which is a conflict in a proprietary target. */
    private void scanWithSbom(long repoId, String... packages) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(START);
        scan.setSbom(write(Map.of("artifacts", Stream.of(packages)
                .map(name -> Map.of("name", name, "version", "1.0.0", "purl", "pkg:generic/" + name + "@1.0.0",
                        "licenses", List.of("GPL-2.0")))
                .toList())));
        scans.save(scan);
    }
}
