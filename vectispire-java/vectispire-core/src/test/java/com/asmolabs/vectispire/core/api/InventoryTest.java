package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * "Do we ship this library, and in which release of ours?"
 *
 * <p>The second half is the one under test. Answering "yes, somewhere" leaves the work undone;
 * the answer that closes it names the project version the component went out in.
 */
@DisplayName("searching the component inventory")
class InventoryTest extends ApiTestBase {

    private static final Instant SCANNED = Instant.parse("2026-03-03T08:00:00Z");

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("answers with the project version the component shipped in")
    void theProjectVersionComesBackWithTheComponent() throws Exception {
        long repositoryId = seedRepository("Arm Libs Spring");
        long scanId = seedScan(repositoryId, "1.17.6");
        seedComponent(scanId, "log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", true);

        mvc.perform(authenticated(get("/api/v1/inventory/search?name=log4j"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.occurrences[0].component").value("log4j-core"))
                .andExpect(jsonPath("$.occurrences[0].componentVersion").value("2.14.1"))
                // The two versions side by side. Confusing them is the one mistake that makes the
                // answer useless, which is why they are named apart on the wire.
                .andExpect(jsonPath("$.occurrences[0].projectVersion").value("1.17.6"))
                .andExpect(jsonPath("$.occurrences[0].targetName").value("Arm Libs Spring"))
                .andExpect(jsonPath("$.occurrences[0].direct").value(true))
                .andExpect(jsonPath("$.truncated").value(false));
    }

    @Test
    @DisplayName("finds a component nothing is wrong with, which the backlog never could")
    void aCleanComponentIsStillFound() throws Exception {
        // The reason this feature is not a filter over issues: on the day a vulnerability is
        // published no scanner knows about it, so the backlog is silent on exactly the component
        // being asked about. No issue is seeded here on purpose.
        long scanId = seedScan(seedRepository("Vectispire"), "0.1.0");
        seedComponent(scanId, "jackson-databind", "2.17.0", "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0", false);

        mvc.perform(authenticated(get("/api/v1/inventory/search?name=jackson"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.occurrences[0].componentVersion").value("2.17.0"))
                .andExpect(jsonPath("$.occurrences[0].direct").value(false));
    }

    @Test
    @DisplayName("an exact version is exact: 2.14.1 is not 2.14.10")
    void theVersionFilterIsNotAPrefix() throws Exception {
        long scanId = seedScan(seedRepository("Arm"), "1.17.6");
        seedComponent(scanId, "log4j-core", "2.14.10", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.10", true);

        // A prefix match here would report a release as affected when it is not — the kind of
        // wrong answer that gets acted on, because it is plausible.
        mvc.perform(authenticated(get("/api/v1/inventory/search?name=log4j&version=2.14.1"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.occurrences").isEmpty());

        mvc.perform(authenticated(get("/api/v1/inventory/search?name=log4j&version=2.14.10"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.occurrences[0].componentVersion").value("2.14.10"));
    }

    @Test
    @DisplayName("matches the package URL too, so an ecosystem can be named")
    void thePurlIsSearchable() throws Exception {
        long scanId = seedScan(seedRepository("Arm"), "1.17.6");
        seedComponent(scanId, "log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", true);

        mvc.perform(authenticated(get("/api/v1/inventory/search?name=org.apache.logging"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.occurrences[0].component").value("log4j-core"));
    }

    @Test
    @DisplayName("the newest scan first, by the scan's creation and not its identifier, then by name")
    void newestScanFirst() throws Exception {
        long repositoryId = seedRepository("Arm");
        // The newer scan is written first, so its identifier is the lower: an order by id would invert them.
        long newer = seedScan(repositoryId, "2.0.0", SCANNED.plusSeconds(3600));
        long older = seedScan(repositoryId, "1.0.0", SCANNED);
        seedComponent(older, "log4j-core", "2.14.1", null, true);
        seedComponent(newer, "log4j-core", "2.17.1", null, true);
        seedComponent(newer, "log4j-api", "2.17.1", null, true);

        mvc.perform(authenticated(get("/api/v1/inventory/search?name=log4j"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.occurrences.length()").value(3))
                .andExpect(jsonPath("$.occurrences[0].component").value("log4j-api"))
                .andExpect(jsonPath("$.occurrences[0].projectVersion").value("2.0.0"))
                .andExpect(jsonPath("$.occurrences[1].component").value("log4j-core"))
                .andExpect(jsonPath("$.occurrences[1].projectVersion").value("2.0.0"))
                .andExpect(jsonPath("$.occurrences[2].projectVersion").value("1.0.0"))
                .andExpect(jsonPath("$.occurrences[2].branch").value("master"));
    }

    @Test
    @DisplayName("a directness nobody established stays unknown rather than becoming transitive")
    void unknownDirectnessIsNotFalse() throws Exception {
        long scanId = seedScan(seedRepository("Arm"), "1.17.6");
        seedComponent(scanId, "mystery-lib", "1.0.0", null, null);

        mvc.perform(authenticated(get("/api/v1/inventory/search?name=mystery"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.occurrences[0].direct").doesNotExist());
    }

    private long seedRepository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("ssh://git@example.com/art/" + name.toLowerCase().replace(' ', '-') + ".git");
        repository.setName(name);
        repository.setBranch("master");
        return repositories.save(repository).getId();
    }

    private long seedScan(long repositoryId, String projectVersion) {
        return seedScan(repositoryId, projectVersion, SCANNED);
    }

    private long seedScan(long repositoryId, String projectVersion, Instant createdAt) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("master");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(createdAt);
        scan.setVersion(projectVersion);
        scan.setProjectType("maven");
        return scans.save(scan).getId();
    }


    @Test
    @DisplayName("the version filter answers for the caller's targets, not the estate's")
    void versionsAreScopedToTheCaller() throws Exception {
        restrict();
        long ours = seedRepository("Ours");
        long theirs = seedRepository("Theirs");
        seedComponent(seedScan(ours, "1.0.0"), "log4j-core", "2.14.1", "pkg:maven/log4j@2.14.1", true);
        seedComponent(seedScan(theirs, "9.9.9"), "log4j-core", "2.17.2", "pkg:maven/log4j@2.17.2", true);

        String reader = asReader();
        assignDirectly(readerId(), ours);

        // **The question this closes is an oracle, not a listing.** Before the scan was joined,
        // this route answered "2.14.1 and 2.17.2" to anybody signed in — so a reader given one
        // repository could learn that somebody else runs a version, which is the whole of what a
        // vulnerability disclosure is worth. Their own version still comes back: the fix is a
        // filter, not a refusal.
        mvc.perform(authenticated(get("/api/v1/inventory/versions?name=log4j"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0]").value("2.14.1"));

        mvc.perform(authenticated(get("/api/v1/inventory/versions?name=log4j"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    @DisplayName("the search answers for the caller's targets, by the target each row carries")
    void searchIsScopedToTheCaller() throws Exception {
        restrict();
        long ours = seedRepository("Ours");
        long theirs = seedRepository("Theirs");
        seedComponent(seedScan(ours, "1.0.0"), "log4j-core", "2.14.1", "pkg:maven/log4j@2.14.1", true);
        seedComponent(seedScan(theirs, "9.9.9"), "log4j-core", "2.17.2", "pkg:maven/log4j@2.17.2", true);

        String reader = asReader();
        assignDirectly(readerId(), ours);

        // The row's own copy of its scan's target (V61) is what the filter reads: another account's
        // release must not come back, nor be counted.
        mvc.perform(authenticated(get("/api/v1/inventory/search?name=log4j"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.occurrences.length()").value(1))
                .andExpect(jsonPath("$.occurrences[0].projectVersion").value("1.0.0"))
                .andExpect(jsonPath("$.total").value(1));
    }

    private void restrict() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
    }

    private void assignDirectly(long userId, long repositoryId) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "repository", "id", repositoryId)))))
                .andExpect(status().isOk());
    }

    /** The reader account's identifier, read back through the administration listing. */
    private long readerId() throws Exception {
        String body = mvc.perform(authenticated(get("/api/v1/users"), asAdmin()))
                .andReturn()
                .getResponse()
                .getContentAsString();
        for (var node : json.readTree(body).path("users")) {
            if (node.path("username").asText("").startsWith("reader-")) {
                return node.path("id").asLong();
            }
        }
        throw new IllegalStateException("no reader account in the listing");
    }

    private void seedComponent(long scanId, String name, String version, String purl, Boolean direct) {
        ComponentEntity component = new ComponentEntity();
        component.setScanId(scanId);
        // The scan's target and instant, as ComponentInventory copies them (V61).
        ScanEntity scanOfComponent = scans.findById(scanId).orElseThrow();
        component.setRepoId(scanOfComponent.getRepoId());
        component.setContainerId(scanOfComponent.getContainerId());
        component.setScanCreatedAt(scanOfComponent.getCreatedAt());
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("java-archive");
        component.setIsDirect(direct);
        components.save(component);
    }
}
