package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.Users;
import com.asmolabs.vectispire.core.outbox.persistence.Outbox;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.platform.MaintenanceJobs;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The security events a SOC expects, each from the gesture that causes it, through the real routes.
 *
 * <p>What is asserted is the row the outbox holds — the event, its actor, address and target —
 * rather than a socket, except for the log-injection case, which is about the bytes that leave.
 * {@code SiemExportRoutesTest} covers the journey from the row to the collector.
 */
@DisplayName("the security events, each from the gesture that causes it")
class SiemSignalsRoutesTest extends ApiTestBase {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired
    private Outbox outbox;

    @Autowired
    private SettingsService settings;

    @Autowired
    private Users users;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private MaintenanceJobs jobs;

    @Autowired
    private com.asmolabs.vectispire.core.access.TotpService totp;

    @Test
    @DisplayName("the sign-in ceiling: an account's sixth wrong password")
    void signInThrottle() throws Exception {
        exportTo("127.0.0.1:9");
        tokenFor("siem-throttled", Role.USER, false);

        for (int attempt = 0; attempt < 6; attempt++) {
            login("siem-throttled", "wrong-on-purpose");
        }

        assertThat(queued("SIGN_IN_THROTTLED")).isNotEmpty().first().satisfies(event -> {
            assertThat(event.at("/extensions/suser").asText()).isEqualTo("siem-throttled");
            assertThat(event.at("/extensions/act").asText()).isEqualTo("LOGIN_BLOCKED");
            assertThat(event.at("/extensions/src").asText()).isNotBlank();
        });
        // An ordinary wrong password is not an event: five of them are the ceiling's business.
        assertThat(queuedTypes()).doesNotContain("ACCOUNT_CHANGED");
    }

    @Test
    @DisplayName("a username typed to forge a second event leaves as one escaped line")
    void aForgedUsernameCannotInjectAnEvent() throws Exception {
        try (DatagramSocket collector = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            collector.setSoTimeout(3_000);
            exportTo("127.0.0.1:" + collector.getLocalPort());

            String forged = "x|y\nCEF:0|Vectispire|ASPM|1|ZAN-SEC-018|forged|10|src=6.6.6.6 suser=admin";
            for (int attempt = 0; attempt < 6; attempt++) {
                login(forged, "wrong");
            }
            jobs.relayNotifications();

            String received = null;
            for (int packet = 0; packet < 10 && received == null; packet++) {
                DatagramPacket datagram = new DatagramPacket(new byte[65_536], 65_536);
                collector.receive(datagram);
                String message = new String(datagram.getData(), 0, datagram.getLength(), StandardCharsets.UTF_8);
                if (message.contains("|ZAN-SEC-007|")) {
                    received = message;
                }
            }

            assertThat(received).isNotNull().doesNotContain("\n").doesNotContain("\r");
            assertThat(received).contains("suser=x|y\\nCEF:0|Vectispire|ASPM|1|ZAN-SEC-018|forged|10|src\\=6.6.6.6 suser\\=admin");
            assertThat(received).doesNotContain(" src=6.6.6.6");
        }
    }

    @Test
    @DisplayName("the MFA ceiling: the wrong code that destroys the challenge, and not the ones before it")
    void mfaCeiling() throws Exception {
        exportTo("127.0.0.1:9");
        String username = mfaAccount();
        String challenge = json.readTree(login(username, PASSWORD)).get("mfa_token").asText();

        verify(challenge, "000001");
        verify(challenge, "000002");
        assertThat(queued("MFA_FAILURE_CEILING")).isEmpty();

        verify(challenge, "000003");
        assertThat(queued("MFA_FAILURE_CEILING")).singleElement()
                .satisfies(event -> assertThat(event.at("/extensions/suser").asText()).isEqualTo(username));
    }

    @Test
    @DisplayName("the bearer-token ceiling: once per window, not once per refusal")
    void bearerThrottle() throws Exception {
        exportTo("127.0.0.1:9");

        for (int attempt = 0; attempt < 65; attempt++) {
            mvc.perform(get("/api/v1/issues").header("Authorization", "Bearer zsk_not-a-real-key"));
        }

        assertThat(queued("BEARER_TOKEN_THROTTLED")).singleElement()
                .satisfies(event -> assertThat(event.at("/extensions/act").asText()).isEqualTo("ACCESS_DENIED"));
    }

    @Test
    @DisplayName("triage: a direct settlement, a request that says nothing, its approval and a refusal")
    void triageDecisions() throws Exception {
        exportTo("127.0.0.1:9");
        long target = repository();
        long settled = issue(target, "CVE-SIEM-1");
        long requested = issue(target, "CVE-SIEM-2");
        long refused = issue(target, "CVE-SIEM-3");

        triage(settled, "not_affected", asAdmin());
        assertThat(queued("TRIAGE_SETTLED")).singleElement()
                .satisfies(event -> assertThat(event.at("/extensions/cs1").asText()).isEqualTo(String.valueOf(settled)));

        String reader = asReader();
        triage(requested, "not_affected", reader);
        triage(refused, "not_affected", reader);
        // Two requests: the four-eyes control working, nothing for a SOC.
        assertThat(queuedTypes()).doesNotContain("TRIAGE_APPROVED", "TRIAGE_REFUSED");
        assertThat(queued("TRIAGE_SETTLED")).hasSize(1);

        String champion = asSecurityChampion();
        triage(requested, "not_affected", champion);
        triage(refused, "under_review", champion);

        assertThat(queued("TRIAGE_APPROVED")).singleElement()
                .satisfies(event -> assertThat(event.at("/extensions/cs1").asText()).isEqualTo(String.valueOf(requested)));
        assertThat(queued("TRIAGE_REFUSED")).singleElement()
                .satisfies(event -> assertThat(event.at("/extensions/cs1").asText()).isEqualTo(String.valueOf(refused)));
    }

    @Test
    @DisplayName("a security setting is forwarded, an SLA window is not")
    void securitySettings() throws Exception {
        exportTo("127.0.0.1:9");

        mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sla_low_days\":\"200\"}"))
                .andExpect(status().isOk());
        assertThat(queued("SECURITY_SETTING_CHANGED")).isEmpty();

        // The platform governor's to decide: the rules the others act under.
        mvc.perform(authenticated(put("/api/v1/settings"), tokenFor("siem-governor", Role.SUPERUSER, false))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"triage_four_eyes_required\":\"false\"}"))
                .andExpect(status().isOk());
        assertThat(queued("SECURITY_SETTING_CHANGED")).singleElement()
                .satisfies(event -> assertThat(event.at("/message").asText()).contains("Four-Eyes"));
    }

    @Test
    @DisplayName("a CI gate refusal, with who asked")
    void gateRefusal() throws Exception {
        exportTo("127.0.0.1:9");
        long target = repository();
        issue(target, "CVE-SIEM-GATE");

        mvc.perform(authenticated(post("/api/v1/gate"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"repository_id\":" + target + ",\"fail_on_severity\":\"high\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passed").value(false));

        assertThat(queued("SECURITY_GATE_FAILED")).singleElement().satisfies(event -> {
            assertThat(event.at("/extensions/suser").asText()).startsWith("admin-");
            assertThat(event.at("/extensions/cs1").asText()).isEqualTo("repository " + target);
        });
    }

    @Test
    @DisplayName("a passing gate says nothing")
    void gatePass() throws Exception {
        exportTo("127.0.0.1:9");
        long target = repository();

        mvc.perform(authenticated(post("/api/v1/gate"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"repository_id\":" + target + "}"))
                .andExpect(jsonPath("$.passed").value(true));

        assertThat(queued("SECURITY_GATE_FAILED")).isEmpty();
    }

    @Test
    @DisplayName("an audit chain that no longer verifies")
    void brokenAuditChain() throws Exception {
        exportTo("127.0.0.1:9");
        mvc.perform(authenticated(get("/api/v1/audit-log/verify"), asAdmin()))
                .andExpect(jsonPath("$.intact").value(true));
        assertThat(queued("AUDIT_CHAIN_BROKEN")).isEmpty();

        // Somebody with the database rewrites what an entry says.
        jdbc.update("update t_audit_log set description = 'nothing happened here'");

        mvc.perform(authenticated(get("/api/v1/audit-log/verify"), asAdmin()))
                .andExpect(jsonPath("$.intact").value(false));
        assertThat(queued("AUDIT_CHAIN_BROKEN")).singleElement()
                .satisfies(event -> assertThat(event.at("/message").asText()).contains("breaks at entry"));
    }

    @Test
    @DisplayName("enrolling a second factor changes an account, and spending a backup code is its own event")
    void backupCode() throws Exception {
        exportTo("127.0.0.1:9");
        UserEntity pending = users.findByUsername(mfaAccount()).orElseThrow();
        pending.setMfaEnabled(false);
        UserEntity user = users.save(pending);
        String secret = totp.setup(UserView.of(user)).secret();
        List<String> codes = totp.enable(UserView.of(user), secret,
                com.asmolabs.vectispire.common.domain.auth.Totp.generateCode(secret, Instant.now())).backupCodes();

        // An operation that signals on its own: USER_UPDATED is an account change whoever writes it.
        assertThat(queued("ACCOUNT_CHANGED")).singleElement()
                .satisfies(event -> assertThat(event.at("/message").asText()).contains("MFA / TOTP enabled"));

        assertThat(totp.verify(users.findById(user.getId()).orElseThrow(), codes.getFirst())).isTrue();

        // The same operation, named by its writer: spending a recovery code is not "an account change".
        assertThat(queued("MFA_BACKUP_CODE_USED")).singleElement()
                .satisfies(event -> assertThat(event.at("/extensions/suser").asText()).isEqualTo(user.getUsername()));
        assertThat(queued("ACCOUNT_CHANGED")).hasSize(1);
    }

    /** Turns the export on, then forgets what the save itself queued, so each test counts its own. */
    @Test
    @DisplayName("filing a repository, and deleting a project that held grants, change who sees what")
    void projectVisibilityChanges() throws Exception {
        exportTo("127.0.0.1:9");
        String admin = asAdmin();
        long solution = json.readTree(mvc.perform(authenticated(post("/api/v1/solutions"), admin)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("name", "siem-" + System.nanoTime()))))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString())
                .get("id").asLong();
        long granted = projectIn(solution, admin);
        long empty = projectIn(solution, admin);

        // Decision 0023: filing moves the repository into every grant on the project at once.
        mvc.perform(authenticated(put("/api/v1/projects/" + granted + "/repositories/" + repository()), admin))
                .andExpect(status().isNoContent());
        assertThat(queued("ACCESS_GRANT_CHANGED")).hasSize(1);

        tokenFor("siem-grantee", Role.USER, false);
        long grantee = users.findByUsername("siem-grantee").orElseThrow().getId();
        mvc.perform(authenticated(put("/api/v1/users/" + grantee + "/targets"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "project", "id", granted)))))
                .andExpect(status().isOk());
        outbox.deleteAll();

        mvc.perform(authenticated(delete("/api/v1/projects/" + empty), admin)).andExpect(status().isNoContent());
        assertThat(queued("ACCESS_GRANT_CHANGED")).as("nobody held the empty project").isEmpty();

        mvc.perform(authenticated(delete("/api/v1/projects/" + granted), admin)).andExpect(status().isNoContent());
        assertThat(queued("ACCESS_GRANT_CHANGED")).singleElement()
                .satisfies(event -> assertThat(event.at("/message").asText()).contains("grant(s) revoked"));
    }

    private long projectIn(long solution, String admin) throws Exception {
        return json.readTree(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), admin)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("name", "p-" + System.nanoTime()))))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString())
                .get("id").asLong();
    }

    private void exportTo(String endpoint) throws Exception {
        settings.set(Setting.NOTIFICATION_ALLOW_PRIVATE_URL, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_UDP", "endpoint": "%s", "minSeverity": "LOW"}"""
                                .formatted(endpoint)))
                .andExpect(status().isOk());
        outbox.deleteAll();
    }

    private List<JsonNode> queued(String eventType) {
        return queuedEvents().stream().filter(event -> event.get("eventType").asText().equals(eventType)).toList();
    }

    private List<String> queuedTypes() {
        return queuedEvents().stream().map(event -> event.get("eventType").asText()).toList();
    }

    private List<JsonNode> queuedEvents() {
        return outbox.findAll().stream()
                .filter(row -> SiemEvents.TYPE.equals(row.getMessageType()))
                .map(row -> {
                    try {
                        return json.readTree(row.getPayload());
                    } catch (Exception unreadable) {
                        throw new IllegalStateException(unreadable);
                    }
                })
                .toList();
    }

    private String login(String username, String password) throws Exception {
        return mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("username", username, "password", password, "client_id", "siem"))))
                .andReturn().getResponse().getContentAsString();
    }

    private void verify(String challenge, String code) throws Exception {
        mvc.perform(post("/api/v1/auth/mfa/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(Map.of("mfa_token", challenge, "code", code))));
    }

    /** MFA on and no secret, so every code is wrong — the refusal path is all this needs. */
    private String mfaAccount() {
        Instant now = Instant.now();
        UserEntity user = new UserEntity();
        user.setUsername("siem-mfa-" + System.nanoTime());
        user.setPassword(PasswordHasher.hash(PASSWORD));
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setMfaEnabled(true);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        return users.save(user).getUsername();
    }

    private void triage(long issue, String status, String token) throws Exception {
        mvc.perform(authenticated(post("/api/v1/issues/" + issue + "/triage"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "status", status,
                                "justification", "vulnerable_code_not_in_execute_path",
                                "comment", "SIEM signal test"))))
                .andExpect(status().isOk());
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/siem-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long issue(long repoId, String identifier) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
