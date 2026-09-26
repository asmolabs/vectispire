package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.asmolabs.vectispire.core.access.persistence.TeamEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamWebhooks;
import com.asmolabs.vectispire.core.access.persistence.Teams;
import com.asmolabs.vectispire.core.repositories.GitTokens;
import com.asmolabs.vectispire.core.repositories.SshKeys;
import com.asmolabs.vectispire.core.rules.persistence.RuleSets;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigs;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * What the credential, channel, rule-set and SIEM forms may hold.
 *
 * <p>Each of these reached a bounded column unchecked, and the deployable engines refused the row
 * at the write, as a 500. SQLite, which this suite runs on, does not enforce a varchar length, so
 * the assertion is the status — the guard is what answers 400, on every engine, first.
 */
@DisplayName("the bounds of the integration forms")
class IntegrationInputBoundsTest extends ApiTestBase {

    private static final String KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----";

    @Autowired
    private GitTokens gitTokens;

    @Autowired
    private SshKeys sshKeys;

    @Autowired
    private RuleSets ruleSets;

    @Autowired
    private SiemConfigs siem;

    @Autowired
    private Teams teams;

    @Autowired
    private TeamWebhooks webhooks;

    @Test
    @DisplayName("an HTTPS token's name, username or token past its ceiling is a 400")
    void gitTokenFieldsAreBounded() throws Exception {
        String admin = asAdmin();
        Map<String, String> valid = Map.of("name", "forge", "host", "github.com", "token", "ghp_abc");
        // Counted rather than asserted empty: the context's cleanup does not list t_git_token, so
        // another class's rows may still be here.
        long before = gitTokens.count();

        assertThat(send(admin, post("/api/v1/git-tokens"), with(valid, "name", "n".repeat(256)))).isEqualTo(400);
        assertThat(send(admin, post("/api/v1/git-tokens"), with(valid, "username", "u".repeat(256)))).isEqualTo(400);
        assertThat(send(admin, post("/api/v1/git-tokens"), with(valid, "token", "t".repeat(8_193)))).isEqualTo(400);
        assertThat(gitTokens.count()).isEqualTo(before);
    }

    @Test
    @DisplayName("an SSH key's name or key past its ceiling is a 400")
    void sshKeyFieldsAreBounded() throws Exception {
        String admin = asAdmin();
        Map<String, String> valid = Map.of("name", "deploy", "private_key", KEY);

        assertThat(send(admin, post("/api/v1/ssh-keys"), with(valid, "name", "n".repeat(256)))).isEqualTo(400);
        assertThat(send(admin, post("/api/v1/ssh-keys"),
                        with(valid, "private_key", KEY + "A".repeat(16_000)))).isEqualTo(400);
        assertThat(send(admin, post("/api/v1/ssh-keys"), with(valid, "public_key", "p".repeat(16_001)))).isEqualTo(400);
        assertThat(sshKeys.findAll()).isEmpty();
    }

    @Test
    @DisplayName("a rule set's name past its column, or an activation note past the text ceiling, is a 400")
    void ruleSetFieldsAreBounded() throws Exception {
        String ciso = asCiso();
        List<Map<String, String>> files = List.of(Map.of("name", "r.yaml", "content", "rules:\n  - id: sqli\n"));

        int refused = mvc.perform(authenticated(post("/api/v1/rule-sets"), ciso)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "n".repeat(256), "files", files))))
                .andReturn().getResponse().getStatus();
        assertThat(refused).isEqualTo(400);
        assertThat(ruleSets.findAll()).isEmpty();

        long id = json.readTree(mvc.perform(authenticated(post("/api/v1/rule-sets"), ciso)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("name", "rules", "files", files))))
                        .andReturn().getResponse().getContentAsString())
                .get("id").asLong();
        int note = send(ciso, post("/api/v1/rule-sets/" + id + "/activate"), Map.of("note", "x".repeat(16_001)));
        assertThat(note).isEqualTo(400);
        assertThat(ruleSets.findById(id).orElseThrow().getIsActive()).isNotEqualTo(Boolean.TRUE);
    }

    @Test
    @DisplayName("a team channel URL past its column is a 400, before any address is resolved")
    void teamWebhookIsBounded() throws Exception {
        TeamEntity team = new TeamEntity();
        team.setName("platform");
        team.setCreatedAt(Instant.now());
        long id = teams.save(team).getId();

        int status = send(asAdmin(), put("/api/v1/teams/" + id + "/webhook"),
                Map.of("url", "https://hooks.example.com/" + "p".repeat(480)));

        assertThat(status).isEqualTo(400);
        assertThat(webhooks.findAll()).isEmpty();
    }

    @Test
    @DisplayName("an unknown SIEM protocol or severity, an oversized endpoint or an unsendable header is a 400")
    void siemFieldsAreValidated() throws Exception {
        String ciso = asCiso();
        Map<String, String> valid = Map.of(
                "protocol", "WEBHOOK", "endpoint", "https://siem.example.com/cef", "minSeverity", "HIGH");

        assertThat(siemSave(ciso, with(valid, "protocol", "CARRIER_PIGEON"))).isEqualTo(400);
        assertThat(siemSave(ciso, with(valid, "minSeverity", "SEVERE"))).isEqualTo(400);
        assertThat(siemSave(ciso, with(valid, "endpoint", "https://siem.example.com/" + "e".repeat(1_000)))).isEqualTo(400);
        assertThat(siemSave(ciso, with(valid, "authHeader", "Bearer abc\r\nX-Injected: 1"))).isEqualTo(400);
        assertThat(siemSave(ciso, with(valid, "authHeader", "Bearer " + "a".repeat(1_500)))).isEqualTo(400);
        assertThat(siem.findAll()).as("a refusal writes nothing").isEmpty();

        // A syslog protocol reads a host:port, not the webhook's URL: the endpoint moves with it.
        assertThat(siemSave(ciso, with(valid, "protocol", "syslog_tls", "minSeverity", "medium"))).isEqualTo(400);
        assertThat(siemSave(ciso, with(valid, "protocol", "syslog_tls", "endpoint", "siem.example.com:6514",
                "minSeverity", "medium"))).isEqualTo(200);
        assertThat(siem.findAll()).singleElement().satisfies(config -> {
            assertThat(config.getProtocol()).isEqualTo("SYSLOG_TLS");
            assertThat(config.getMinSeverity()).isEqualTo("MEDIUM");
        });
    }

    private int siemSave(String token, Map<String, String> fields) throws Exception {
        Map<String, Object> body = new java.util.HashMap<>(fields);
        body.put("enabled", true);
        return mvc.perform(authenticated(put("/api/v1/siem/config"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andReturn().getResponse().getStatus();
    }

    private static Map<String, String> with(Map<String, String> base, String... overrides) {
        Map<String, String> copy = new java.util.HashMap<>(base);
        for (int i = 0; i < overrides.length; i += 2) {
            copy.put(overrides[i], overrides[i + 1]);
        }
        return copy;
    }

    private int send(String token, MockHttpServletRequestBuilder request, Map<String, String> body) throws Exception {
        return mvc.perform(authenticated(request, token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andReturn().getResponse().getStatus();
    }
}
