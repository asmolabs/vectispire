package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.asmolabs.vectispire.core.targets.persistence.Containers;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * What a repository or an image form may hold, refused at the door rather than by the database.
 *
 * <p><b>Why over HTTP, and why the assertion is the status.</b> This suite runs on SQLite, which
 * does not enforce a {@code varchar} length: a 300-character branch is stored here and refused by
 * MySQL and PostgreSQL at the write, as a 500. So a test that only checked "the row is not stored"
 * would be green without the guard on SQLite and meaningless on the others. The guard is what
 * answers 400, on every engine, before the database is asked.
 */
@DisplayName("the bounds of a target form")
class TargetInputBoundsTest extends ApiTestBase {

    private static final String URL = "ssh://git@example.com/team/alpha.git";

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Containers containers;

    @Test
    @DisplayName("a repository field past its column is a 400, on create and on update")
    void repositoryFieldsAreBounded() throws Exception {
        String admin = asAdmin();
        String tooLong = "a".repeat(256);

        for (String field : new String[] {"branch", "name", "required_agent_label"}) {
            assertThat(send(admin, post("/api/v1/repositories"), Map.of("url", URL, field, tooLong)))
                    .as("create with a 256-character %s", field)
                    .isEqualTo(400);
        }
        assertThat(send(admin, post("/api/v1/repositories"),
                        Map.of("url", "ssh://git@example.com/" + "a".repeat(250) + ".git")))
                .as("create with a URL past 255 characters")
                .isEqualTo(400);
        assertThat(repositories.findAll()).isEmpty();

        long id = existingRepository();
        for (String field : new String[] {"branch", "name", "required_agent_label"}) {
            assertThat(send(admin, patch("/api/v1/repositories/" + id), Map.of(field, tooLong)))
                    .as("update with a 256-character %s", field)
                    .isEqualTo(400);
        }

        assertThat(send(admin, post("/api/v1/repositories"), Map.of("url", URL, "name", "a".repeat(255))))
                .as("a name exactly as wide as the column is accepted")
                .isEqualTo(200);
    }

    @Test
    @DisplayName("an SSH key identifier that names no key is a 400, not a foreign-key 500")
    void anAbsentSshKeyIsRefused() throws Exception {
        String admin = asAdmin();
        String nobody = UUID.randomUUID().toString();

        assertThat(send(admin, post("/api/v1/repositories"), Map.of("url", URL, "sshKeyId", nobody)))
                .isEqualTo(400);
        assertThat(repositories.findAll()).isEmpty();

        long id = existingRepository();
        assertThat(send(admin, patch("/api/v1/repositories/" + id), Map.of("sshKeyId", nobody)))
                .isEqualTo(400);
        assertThat(repositories.findById(id).orElseThrow().getSshKeyId()).isNull();
    }

    @Test
    @DisplayName("an unknown tier is a 400 rather than a silent tier 2, and a real one is kept")
    void anUnknownTierIsRefused() throws Exception {
        String admin = asAdmin();

        assertThat(send(admin, post("/api/v1/repositories"), Map.of("url", URL, "tier", "TIER_1")))
                .isEqualTo(400);
        assertThat(send(admin, post("/api/v1/containers"), Map.of("image_name", "nginx", "tier", "gold")))
                .isEqualTo(400);
        assertThat(repositories.findAll()).isEmpty();
        assertThat(containers.findAll()).isEmpty();

        long id = existingRepository();
        assertThat(send(admin, patch("/api/v1/repositories/" + id), Map.of("tier", "tier_one"))).isEqualTo(400);
        assertThat(send(admin, patch("/api/v1/repositories/" + id), Map.of("tier", "tier_1_mission_critical")))
                .isEqualTo(200);
        assertThat(repositories.findById(id).orElseThrow().getTier()).isEqualTo("TIER_1_MISSION_CRITICAL");
    }

    @Test
    @DisplayName("an image registry or name past its column is a 400")
    void imageFieldsAreBounded() throws Exception {
        String admin = asAdmin();

        assertThat(send(admin, post("/api/v1/containers"), Map.of("image_name", "a".repeat(256))))
                .isEqualTo(400);
        assertThat(send(admin, post("/api/v1/containers"),
                        Map.of("registry", "r".repeat(256), "image_name", "nginx")))
                .isEqualTo(400);
        assertThat(send(admin, post("/api/v1/containers"),
                        Map.of("image_name", "nginx", "required_agent_label", "l".repeat(256))))
                .isEqualTo(400);
        assertThat(containers.findAll()).isEmpty();
    }

    private long existingRepository() {
        RepositoryEntity row = new RepositoryEntity();
        row.setUrl("ssh://git@example.com/team/existing.git");
        row.setBranch("main");
        return repositories.save(row).getId();
    }

    private int send(
            String token,
            org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request,
            Map<String, String> body) throws Exception {
        return mvc.perform(authenticated(request, token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andReturn().getResponse().getStatus();
    }
}
