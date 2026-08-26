package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Components;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
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
 * "Do we ship this library, and in which release of ours?"
 *
 * <p>The second half is the one under test. Answering "yes, somewhere" leaves the work undone;
 * the answer that closes it names the project version the component went out in.
 */
@DisplayName("searching the component inventory")
class InventoryTest extends ApiTestBase {

    private static final Instant SCANNED = Instant.parse("2026-03-03T08:00:00Z");

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private Components components;

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
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("master");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(SCANNED);
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
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("java-archive");
        component.setIsDirect(direct);
        components.save(component);
    }
}
