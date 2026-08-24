package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.core.persistence.ComponentEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Components;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Scans;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

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
        long scanId = seedScan(seedRepository("Zanshin"), "0.1.0");
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
