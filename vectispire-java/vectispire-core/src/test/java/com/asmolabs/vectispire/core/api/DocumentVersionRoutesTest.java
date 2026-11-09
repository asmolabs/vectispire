package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Every document Vectispire signs or hands over names the version Gradle built.
 *
 * <p>Six documents stated a producer version — the OpenAPI document too, at 4.1.0 — and they took it from four places: two literals
 * ({@code 1.0.0} in the scan CSAF, {@code 0.9.0} in CycloneDX and the attestation), a configuration
 * default and a domain fallback. None of them was checked at the level a reader sees — the served
 * document — which is how the scan CSAF kept announcing a release that does not exist after the
 * others were aligned. One assertion per route, against {@code gradle.properties}.
 */
@DisplayName("the version stated in every exported document")
class DocumentVersionRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    private String admin;
    private long repoId;
    private long scanId;
    private String built;

    @BeforeEach
    void setUp() throws Exception {
        admin = asAdmin();
        RepositoryEntity repository = new RepositoryEntity();
        repository.setName("corp/payments");
        repository.setUrl("https://example.invalid/corp/payments.git");
        repository.setBranch("main");
        repoId = repositories.save(repository).getId();
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setSbom("{\"artifacts\":[]}");
        scan.setCreatedAt(Instant.now());
        scanId = scans.save(scan).getId();
        built = gradleVersion();
    }

    @Test
    @DisplayName("SARIF")
    void sarif() throws Exception {
        mvc.perform(authenticated(get("/api/v1/targets/repository/" + repoId + "/issues.sarif"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.runs[0].tool.driver.version").value(built));
    }

    @Test
    @DisplayName("CSAF, for a target and for a scan")
    void csaf() throws Exception {
        mvc.perform(authenticated(get("/api/v1/targets/repository/" + repoId + "/issues.csaf.json"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.document.tracking.generator.engine.version").value(built));
        mvc.perform(authenticated(get("/api/v1/csaf/scans/" + scanId + "/csaf.json"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.document.tracking.generator.engine.version").value(built));
    }

    @Test
    @DisplayName("CycloneDX")
    void cycloneDx() throws Exception {
        mvc.perform(authenticated(get("/api/v1/cyclonedx/scans/" + scanId + "/cyclonedx-vex.json"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.metadata.tools[0].version").value(built));
    }

    @Test
    @DisplayName("the OpenAPI document, which announced 4.1.0")
    void openApi() throws Exception {
        mvc.perform(authenticated(get("/v3/api-docs"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.info.version").value(built));
    }

    @Test
    @DisplayName("the aggregate CycloneDX root, which is not a release, carries no version and no null fields")
    void theAggregateRootIsNotVersioned() throws Exception {
        // It said 1.0.0 for "the monitored fleet", and serialised "purl": null and "scope": null:
        // the NON_NULL on the document did not reach the records nested in it.
        mvc.perform(authenticated(get("/api/v1/cyclonedx/aggregate.json"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.metadata.component.name").value("vectispire-monitored-fleet"))
                .andExpect(jsonPath("$.metadata.component.version").doesNotExist())
                .andExpect(jsonPath("$.metadata.component.purl").doesNotExist())
                .andExpect(jsonPath("$.metadata.component.scope").doesNotExist())
                .andExpect(jsonPath("$.metadata.tools[0].version").value(built));
    }

    @Test
    @DisplayName("the in-toto attestation")
    void attestation() throws Exception {
        mvc.perform(authenticated(get("/api/v1/attestations/scans/" + scanId), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.predicate.builder.version").value(built));
    }

    private static String gradleVersion() throws Exception {
        Path directory = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (directory != null && !Files.exists(directory.resolve("vectispire-java/gradle.properties"))
                && !Files.exists(directory.resolve("gradle.properties"))) {
            directory = directory.getParent();
        }
        Path file = Files.exists(directory.resolve("gradle.properties"))
                ? directory.resolve("gradle.properties")
                : directory.resolve("vectispire-java/gradle.properties");
        Matcher matcher = Pattern.compile("^version=(.+)$", Pattern.MULTILINE)
                .matcher(Files.readString(file, StandardCharsets.UTF_8));
        if (!matcher.find()) {
            throw new AssertionError("gradle.properties states no version");
        }
        return matcher.group(1).trim();
    }
}
