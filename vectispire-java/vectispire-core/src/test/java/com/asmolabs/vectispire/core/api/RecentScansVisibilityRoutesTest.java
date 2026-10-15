package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * The home page's recent scans, for a scan that names both a repository and an image.
 *
 * <p>Such a scan is its repository's — {@code ScanEntity.target()}, what {@code Visibility.permits} is asked
 * everywhere, and what the scan history already applied in its statement. The recent scans had a query of
 * their own that matched either column, so a reader granted the image and not the repository was shown the
 * scan on the home page: the hidden repository's id, its name, and the scan's status, findings count and
 * error. A reader granted both was shown it twice, once through each batch.
 *
 * <p>The scans are dated in the future so that they are the estate's newest whatever earlier tests of this
 * context left: the administrator's eight are the deployment's eight, and must hold these.
 */
@DisplayName("the dashboard's recent scans")
class RecentScansVisibilityRoutesTest extends ApiTestBase {

    private static final Instant FUTURE = Instant.parse("2090-01-01T00:00:00Z");

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private UserRepository users;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("a scan naming a hidden repository is not shown through the image it also names")
    void aHiddenRepositoryStaysHiddenBehindItsImage() throws Exception {
        String hiddenName = "recent-hidden-" + System.nanoTime();
        long hidden = repository(hiddenName);
        long image = container("recent-image");
        long imageOnly = scan(null, image, FUTURE);
        long both = scan(hidden, image, FUTURE.plusSeconds(1));
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String reader = readerGranted(List.of(Map.of("kind", "container", "id", image)));

        JsonNode recent = recentScans(reader);

        assertThat(ids(recent)).containsExactly(imageOnly);
        // Not the row, and nothing of the repository on any other: its id and its name are what leaked.
        assertThat(ids(recent)).doesNotContain(both);
        assertThat(recent.findValues("repoId")).allMatch(JsonNode::isNull);
        assertThat(recent.toString()).doesNotContain(hiddenName);
    }

    @Test
    @DisplayName("a reader granted the repository and the image sees the scan naming both, once")
    void aReaderOfBothSeesItOnce() throws Exception {
        long repository = repository("recent-both");
        long image = container("recent-both-image");
        long imageOnly = scan(null, image, FUTURE.plusSeconds(10));
        long both = scan(repository, image, FUTURE.plusSeconds(11));
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String reader = readerGranted(List.of(
                Map.of("kind", "repository", "id", repository), Map.of("kind", "container", "id", image)));

        JsonNode recent = recentScans(reader);

        // Matched once through each column, it was listed twice.
        assertThat(ids(recent)).containsExactly(both, imageOnly);
        assertThat(recent.get(0).get("repoId").asLong()).isEqualTo(repository);
    }

    @Test
    @DisplayName("an administrator sees the scan naming both")
    void anAdministratorSeesIt() throws Exception {
        long repository = repository("recent-admin");
        long image = container("recent-admin-image");
        long both = scan(repository, image, FUTURE.plusSeconds(20));
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());

        assertThat(ids(recentScans(asAdmin()))).contains(both);
    }

    @Test
    @DisplayName("an API key restricted to the image does not reach the dashboard at all")
    void aKeyRestrictedToTheImageReadsNothing() throws Exception {
        long hidden = repository("recent-key-hidden");
        long image = container("recent-key-image");
        scan(hidden, image, FUTURE.plusSeconds(30));
        String key = issueKey(Map.of("name", "recent-" + System.nanoTime(), "scopes", List.of("read"),
                "target_kind", "container", "target_id", image));

        // The dashboard accepts no integration key (CredentialConfinement), so the key's narrowing never
        // comes to the recent scans: refused before any is read, whatever the image names.
        String body = mvc.perform(authenticated(get("/api/v1/dashboard"), key))
                .andExpect(status().isForbidden())
                .andReturn().getResponse().getContentAsString();
        assertThat(body).contains("does not accept an API key").doesNotContain("recent-key-hidden");
    }

    private JsonNode recentScans(String token) throws Exception {
        String body = mvc.perform(authenticated(get("/api/v1/dashboard"), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body).get("recentScans");
    }

    private static List<Long> ids(JsonNode rows) {
        return StreamSupport.stream(rows.spliterator(), false).map(row -> row.get("id").asLong()).toList();
    }

    private String readerGranted(List<Map<String, Object>> targets) throws Exception {
        String name = "recent-reader-" + System.nanoTime();
        String reader = tokenFor(name, Role.USER, false);
        long id = users.findByUsername(name).orElseThrow().getId();
        mvc.perform(authenticated(put("/api/v1/users/" + id + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(targets)))
                .andExpect(status().isOk());
        return reader;
    }

    private String issueKey(Map<String, Object> body) throws Exception {
        String response = mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(response).get("secret").asText();
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
}
