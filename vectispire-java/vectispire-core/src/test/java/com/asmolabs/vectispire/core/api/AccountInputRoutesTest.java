package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserTargetRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * What an account form and an account's visible targets may hold.
 *
 * <p>The target list reached the table as sent: {@code [null]} or an entry without an id was a 500
 * from the insert, and an unknown kind was stored — an assignment the screen showed and that granted
 * nothing. The account form's e-mail and display name reached their {@code varchar(255)} unchecked,
 * which SQLite accepts and the deployable engines refuse at the write; the status is the assertion
 * for that reason.
 */
@DisplayName("the account input routes")
class AccountInputRoutesTest extends ApiTestBase {

    @Autowired
    private UserRepository users;

    @Autowired
    private UserTargetRepository assignments;

    @Test
    @DisplayName("an e-mail or display name past its column is a 400, and no account is created")
    void identityFieldsAreBounded() throws Exception {
        String admin = asAdmin();

        for (String field : new String[] {"email", "display_name"}) {
            Map<String, String> body = new HashMap<>(Map.of(
                    "username", "long-" + field.replace('_', '-'),
                    "password", "correct horse battery staple"));
            body.put(field, "a".repeat(251) + "@x.io");
            int status = mvc.perform(authenticated(post("/api/v1/users"), admin)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(body)))
                    .andReturn().getResponse().getStatus();
            assertThat(status).as("create with a 256-character %s", field).isEqualTo(400);
            assertThat(users.findByUsername(body.get("username"))).isEmpty();
        }
    }

    @Test
    @DisplayName("a directory attribute past its column is a SCIM 400, and no account is provisioned")
    void scimAttributesAreBounded() throws Exception {
        int status = mvc.perform(authenticated(post("/scim/v2/Users"), asAdmin())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-long", "displayName", "d".repeat(256)))))
                .andReturn().getResponse().getStatus();

        assertThat(status).isEqualTo(400);
        assertThat(users.findByUsername("scim-long")).isEmpty();
    }

    @Test
    @DisplayName("a null entry, or one with no id, is skipped, and what is answered is what was stored")
    void nullsAreSkipped() throws Exception {
        long id = account("targets-nulls");
        String body = "[null, {\"kind\":\"repository\"}, {\"kind\":\"Repository\",\"id\":7},"
                + " {\"kind\":\"repository\",\"id\":7}, {\"kind\":\"container\",\"id\":3}]";

        MvcResult result = setTargets(id, body);

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        List<Map<String, Object>> answered = json.readValue(
                result.getResponse().getContentAsString(),
                new com.fasterxml.jackson.core.type.TypeReference<List<Map<String, Object>>>() {});
        assertThat(answered)
                .as("the kind lowercased, the duplicate collapsed, the unusable entries gone — and each "
                        + "named, here as deleted since neither target was ever created")
                .containsExactly(
                        Map.of("kind", "repository", "id", 7, "name", "deleted target"),
                        Map.of("kind", "container", "id", 3, "name", "deleted target"));
        assertThat(assignments.findByUserId(id)).hasSize(2);
    }

    @Test
    @DisplayName("an unknown or missing kind is a 400, and the previous assignments stay")
    void anUnknownKindIsRefused() throws Exception {
        long id = account("targets-kind");
        assertThat(setTargets(id, "[{\"kind\":\"repository\",\"id\":1}]").getResponse().getStatus())
                .isEqualTo(200);

        assertThat(setTargets(id, "[{\"kind\":\"folder\",\"id\":2}]").getResponse().getStatus()).isEqualTo(400);
        assertThat(setTargets(id, "[{\"id\":2}]").getResponse().getStatus()).isEqualTo(400);

        assertThat(assignments.findByUserId(id)).hasSize(1);
    }

    private long account(String username) {
        tokenFor(username, Role.USER, false);
        return users.findByUsername(username).orElseThrow().getId();
    }

    private MvcResult setTargets(long id, String body) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/users/" + id + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn();
    }
}
