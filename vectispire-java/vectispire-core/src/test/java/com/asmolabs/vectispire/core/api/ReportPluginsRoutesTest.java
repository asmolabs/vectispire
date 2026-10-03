package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.reportplugins.ReportPluginService;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.ResultActions;

/**
 * The report plugins' registry (decision 0035 §4, lot R2), through the real routes, filter chain and
 * database: who registers, who approves which digest under four-eyes, who switches a plugin on for which
 * project, what a withdrawal closes — and what reaches the audit log and the SIEM.
 */
@DisplayName("report plugins' registry, through the routes")
class ReportPluginsRoutesTest extends ApiTestBase {

    static final String IMAGE_A = "registry.example.internal/reports/summary@sha256:" + "a".repeat(64);
    static final String IMAGE_B = "registry.example.internal/reports/summary@sha256:" + "b".repeat(64);
    static final String IMAGE_C = "registry.example.internal/reports/summary@sha256:" + "c".repeat(64);
    static final String PROJECT_NOT_FOUND = "Project not found.";

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private UserRepository users;

    @Autowired
    private ReportPluginService service;

    private String governor;
    private long project;

    @BeforeEach
    void estate() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        governor = governor();
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Payments " + System.nanoTime()))))
                .andExpect(status().isCreated()));
        project = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Checkout"))))
                .andExpect(status().isCreated()));
    }

    static Map<String, Object> manifest(String image) {
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("id", "summary");
        manifest.put("name", "Quarterly summary");
        manifest.put("image", image);
        manifest.put("export_schema", 1);
        manifest.put("arguments", List.of("--in", "{input}", "--out", "{output}"));
        manifest.put("output", "summary.xlsx");
        manifest.put("media_type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        manifest.put("signature", Map.of(
                "identity", "https://ci.example.internal/reports/summary/release@refs/tags/v1",
                "issuer", "https://ci.example.internal/oidc"));
        return manifest;
    }

    private String governor() {
        return tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
    }

    private ResultActions register(String token, Map<String, Object> manifest) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/report-plugins"), token)
                .contentType(MediaType.APPLICATION_JSON).content(write(manifest)));
    }

    private ResultActions update(String token, Map<String, Object> manifest) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/report-plugins/summary"), token)
                .contentType(MediaType.APPLICATION_JSON).content(write(manifest)));
    }

    private ResultActions approve(String token, String digest) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/report-plugins/summary/manifests/" + digest + "/approval"), token));
    }

    private ResultActions withdraw(String token, String digest, String justification) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/report-plugins/summary/manifests/" + digest + "/withdrawal"), token)
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("justification", justification))));
    }

    private ResultActions activate(String token, long projectId) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/projects/" + projectId + "/report-plugins/summary"), token));
    }

    private JsonNode body(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }

    private long idOf(ResultActions result) throws Exception {
        return body(result).path("id").asLong();
    }

    /** The digest a registration or an update made pending — or, with four-eyes off, approved. */
    private static String newest(JsonNode plugin) {
        return plugin.at("/manifests/0/digest").asText();
    }

    private List<AuditLogEntity> entries(AuditOperation operation) {
        return auditLog.findAll().stream().filter(entry -> operation.wireName().equals(entry.getOperationType())).toList();
    }

    private static void assertConflict(ResultActions result, String cause) throws Exception {
        result.andExpect(status().isConflict()).andExpect(jsonPath("$.type").value("urn:vectispire:problem:" + cause));
    }

    @Nested
    @DisplayName("registering")
    class Registering {

        @Test
        @DisplayName("is the platform governor's alone: an administrator, a CISO and a reader are refused")
        void governorOnly() throws Exception {
            register(asAdmin(), manifest(IMAGE_A)).andExpect(status().isForbidden());
            register(asCiso(), manifest(IMAGE_A)).andExpect(status().isForbidden());
            register(asReader(), manifest(IMAGE_A)).andExpect(status().isForbidden());
            assertThat(entries(AuditOperation.REPORT_PLUGIN_REGISTERED)).isEmpty();

            JsonNode plugin = body(register(governor, manifest(IMAGE_A)).andExpect(status().isCreated()));
            assertThat(plugin.at("/id").asText()).isEqualTo("summary");
            assertThat(plugin.at("/manifests/0/manifest/media_type").asText())
                    .isEqualTo("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            assertThat(plugin.at("/manifests/0/manifest/max_output_bytes").asLong()).isEqualTo(20L * 1024 * 1024);
            assertThat(entries(AuditOperation.REPORT_PLUGIN_REGISTERED)).hasSize(1);

            // Reading the registry is governance reading.
            mvc.perform(authenticated(get("/api/v1/report-plugins"), asReader())).andExpect(status().isForbidden());
            mvc.perform(authenticated(get("/api/v1/report-plugins"), asAuditor()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].id").value("summary"));
        }

        @Test
        @DisplayName("refuses a manifest with no signer, a type off the list, an export major not produced, a moving image")
        void refusals() throws Exception {
            Map<String, Object> unsigned = manifest(IMAGE_A);
            unsigned.remove("signature");
            register(governor, unsigned).andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(org.hamcrest.Matchers.containsString("no waiver")));

            Map<String, Object> html = manifest(IMAGE_A);
            html.put("media_type", "text/html");
            html.put("output", "summary.html");
            register(governor, html).andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(org.hamcrest.Matchers.containsString("not offered")));

            Map<String, Object> future = manifest(IMAGE_A);
            future.put("export_schema", 2);
            register(governor, future).andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(org.hamcrest.Matchers.containsString("major 1, not 2")));

            Map<String, Object> tagged = manifest(IMAGE_A);
            tagged.put("image", "registry.example.internal/reports/summary:latest");
            register(governor, tagged).andExpect(status().isBadRequest());

            assertThat(entries(AuditOperation.REPORT_PLUGIN_REGISTERED)).isEmpty();
        }

        @Test
        @DisplayName("never reuses an id")
        void idNotReused() throws Exception {
            register(governor, manifest(IMAGE_A)).andExpect(status().isCreated());
            assertConflict(register(governor(), manifest(IMAGE_B)), "report-plugin-id-taken");
        }
    }

    @Nested
    @DisplayName("four-eyes on")
    class FourEyesOn {

        @BeforeEach
        void on() {
            settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");
        }

        @Test
        @DisplayName("a registration waits; its registrant cannot approve it; a non-governance account cannot; another can")
        void secondPersonApproves() throws Exception {
            JsonNode registered = body(register(governor, manifest(IMAGE_A)).andExpect(status().isCreated()));
            String digest = newest(registered);
            assertThat(registered.at("/approvedDigest").isNull()).isTrue();
            assertThat(registered.at("/pendingDigest").asText()).isEqualTo(digest);
            assertThat(registered.at("/manifests/0/status").asText()).isEqualTo("pending_approval");

            // Not activatable while it waits.
            assertConflict(activate(asCiso(), project), "report-plugin-not-approved");

            assertConflict(approve(governor, digest), "report-plugin-four-eyes");
            approve(asReader(), digest).andExpect(status().isForbidden());
            approve(asSecurityChampion(), digest).andExpect(status().isForbidden());
            approve(asAuditor(), digest).andExpect(status().isForbidden());
            assertThat(entries(AuditOperation.REPORT_PLUGIN_APPROVED)).isEmpty();

            JsonNode approved = body(approve(asCiso(), digest).andExpect(status().isOk()));
            assertThat(approved.at("/approvedDigest").asText()).isEqualTo(digest);
            assertThat(approved.at("/pendingDigest").isNull()).isTrue();
            assertThat(approved.at("/manifests/0/status").asText()).isEqualTo("approved");
            assertThat(approved.at("/manifests/0/approvalFourEyes").asBoolean()).isTrue();
            assertThat(entries(AuditOperation.REPORT_PLUGIN_APPROVED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains(digest, "four-eyes required"));

            assertConflict(approve(asAdmin(), digest), "report-plugin-not-pending");
            activate(asCiso(), project).andExpect(status().isOk());
        }

        @Test
        @DisplayName("the service refuses an approver who does not write governance, whatever route reaches it")
        void serviceChecksTheRole() throws Exception {
            String digest = newest(body(register(governor, manifest(IMAGE_A))));
            String username = "champion-" + System.nanoTime();
            tokenFor(username, Role.SECURITY_CHAMPION, false);
            UserView champion = UserView.of(users.findByUsername(username).orElseThrow());
            assertThatThrownBy(() -> service.approve("summary", digest, champion,
                    new RequestActor(username, "127.0.0.1", null)))
                    .isInstanceOf(AccessDeniedException.class);
            assertThat(entries(AuditOperation.REPORT_PLUGIN_APPROVED)).isEmpty();
        }

        @Test
        @DisplayName("another governor may approve: the rule is the person, not the role")
        void anotherGovernor() throws Exception {
            String digest = newest(body(register(governor, manifest(IMAGE_A))));
            approve(governor(), digest).andExpect(status().isOk());
        }

        @Test
        @DisplayName("an update waits while the approved digest serves; a later one sets the earlier aside")
        void updateWaits() throws Exception {
            String first = newest(body(register(governor, manifest(IMAGE_A))));
            approve(asAdmin(), first).andExpect(status().isOk());

            JsonNode updated = body(update(governor, manifest(IMAGE_B)).andExpect(status().isOk()));
            String second = newest(updated);
            assertThat(updated.at("/approvedDigest").asText()).isEqualTo(first);
            assertThat(updated.at("/pendingDigest").asText()).isEqualTo(second);

            JsonNode again = body(update(governor, manifest(IMAGE_C)).andExpect(status().isOk()));
            String third = newest(again);
            assertThat(again.at("/pendingDigest").asText()).isEqualTo(third);
            assertThat(statusOf(again, second)).isEqualTo("superseded");
            assertConflict(approve(asAdmin(), second), "report-plugin-not-pending");

            JsonNode approved = body(approve(asAdmin(), third).andExpect(status().isOk()));
            assertThat(approved.at("/approvedDigest").asText()).isEqualTo(third);
            assertThat(statusOf(approved, first)).isEqualTo("approved");
            assertThat(entries(AuditOperation.REPORT_PLUGIN_UPDATED)).hasSize(2);

            // Back to a digest two people approved: at once, no second approval.
            JsonNode back = body(update(governor, manifest(IMAGE_A)).andExpect(status().isOk()));
            assertThat(back.at("/approvedDigest").asText()).isEqualTo(first);
            assertThat(back.at("/pendingDigest").isNull()).isTrue();
        }
    }

    @Nested
    @DisplayName("four-eyes off")
    class FourEyesOff {

        @Test
        @DisplayName("a registration and an update serve at once, and say so")
        void atOnce() throws Exception {
            JsonNode registered = body(register(governor, manifest(IMAGE_A)).andExpect(status().isCreated()));
            String first = newest(registered);
            assertThat(registered.at("/approvedDigest").asText()).isEqualTo(first);
            assertThat(registered.at("/pendingDigest").isNull()).isTrue();
            assertThat(registered.at("/manifests/0/status").asText()).isEqualTo("approved");
            assertThat(registered.at("/manifests/0/approvalFourEyes").asBoolean()).isFalse();
            assertThat(entries(AuditOperation.REPORT_PLUGIN_REGISTERED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("four-eyes off"));

            JsonNode updated = body(update(governor, manifest(IMAGE_B)).andExpect(status().isOk()));
            assertThat(updated.at("/approvedDigest").asText()).isEqualTo(newest(updated)).isNotEqualTo(first);
            activate(asCiso(), project).andExpect(status().isOk());

            // The same manifest again changes nothing and records nothing.
            update(governor, manifest(IMAGE_B)).andExpect(status().isOk());
            assertThat(entries(AuditOperation.REPORT_PLUGIN_UPDATED)).hasSize(1);
        }

        @Test
        @DisplayName("a manifest pending from before the switch is approved by its registrant once four-eyes is off")
        void pendingFromBefore() throws Exception {
            settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");
            String digest = newest(body(register(governor, manifest(IMAGE_A))));
            settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
            JsonNode approved = body(approve(governor, digest).andExpect(status().isOk()));
            assertThat(approved.at("/manifests/0/approvalFourEyes").asBoolean()).isFalse();
        }
    }

    @Nested
    @DisplayName("withdrawing")
    class Withdrawing {

        @Test
        @DisplayName("is the governor's, in writing; the digest never serves nor registers again, and cannot be activated")
        void withdrawal() throws Exception {
            String digest = newest(body(register(governor, manifest(IMAGE_A))));
            String reason = "The renderer dropped accepted issues from the summary sheet.";

            withdraw(asAdmin(), digest, reason).andExpect(status().isForbidden());
            withdraw(asCiso(), digest, reason).andExpect(status().isForbidden());
            withdraw(governor, digest, "wrong").andExpect(status().isBadRequest());
            mvc.perform(authenticated(post("/api/v1/report-plugins/summary/manifests/" + "f".repeat(64) + "/withdrawal"),
                            governor).contentType(MediaType.APPLICATION_JSON).content(write(Map.of("justification", reason))))
                    .andExpect(status().isNotFound());

            JsonNode withdrawn = body(withdraw(governor, digest, reason).andExpect(status().isOk()));
            assertThat(withdrawn.at("/approvedDigest").isNull()).isTrue();
            assertThat(withdrawn.at("/manifests/0/status").asText()).isEqualTo("withdrawn");
            assertThat(withdrawn.at("/manifests/0/withdrawalJustification").asText()).isEqualTo(reason);
            assertThat(entries(AuditOperation.REPORT_PLUGIN_WITHDRAWN)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription())
                            .contains(digest, "(was approved, 0 document(s) withdrawn with it): " + reason));

            assertConflict(activate(asCiso(), project), "report-plugin-not-approved");
            assertConflict(update(governor, manifest(IMAGE_A)), "report-plugin-withdrawn");
            assertConflict(withdraw(governor, digest, reason), "report-plugin-withdrawn");
        }

        @Test
        @DisplayName("a pending digest withdrawn can no longer be approved")
        void pendingWithdrawn() throws Exception {
            settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");
            String digest = newest(body(register(governor, manifest(IMAGE_A))));
            withdraw(governor, digest, "Registered from the wrong pipeline run.").andExpect(status().isOk());
            assertConflict(approve(asCiso(), digest), "report-plugin-not-pending");
        }
    }

    @Nested
    @DisplayName("activating per project")
    class Activating {

        @Test
        @DisplayName("is the security lead's; repeating it records nothing; a missing project is 404 in the guard's words")
        void securityLead() throws Exception {
            register(governor, manifest(IMAGE_A)).andExpect(status().isCreated());

            activate(asReader(), project).andExpect(status().isForbidden());
            activate(asAuditor(), project).andExpect(status().isForbidden());
            activate(asSecurityChampion(), project).andExpect(status().isForbidden());

            String ciso = asCiso();
            activate(ciso, project).andExpect(status().isOk())
                    .andExpect(jsonPath("$.pluginId").value("summary"))
                    .andExpect(jsonPath("$.pluginName").value("Quarterly summary"))
                    .andExpect(jsonPath("$.projectId").value(project));
            activate(ciso, project).andExpect(status().isOk());
            assertThat(entries(AuditOperation.REPORT_PLUGIN_ACTIVATED)).hasSize(1);

            assertThat(detailOf(activate(ciso, project + 100_000).andExpect(status().isNotFound()).andReturn()))
                    .isEqualTo(PROJECT_NOT_FOUND);
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/report-plugins/nothing"), ciso))
                    .andExpect(status().isNotFound());

            mvc.perform(authenticated(get("/api/v1/projects/" + project + "/report-plugins"), asAuditor()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].pluginId").value("summary"));

            mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/report-plugins/summary"), ciso))
                    .andExpect(status().isNoContent());
            mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/report-plugins/summary"), ciso))
                    .andExpect(status().isNotFound());
            assertThat(entries(AuditOperation.REPORT_PLUGIN_DEACTIVATED)).hasSize(1);
        }

        @Test
        @DisplayName("a project the caller does not see whole is read as absent")
        void hiddenProject() throws Exception {
            register(governor, manifest(IMAGE_A)).andExpect(status().isCreated());
            activate(asCiso(), project).andExpect(status().isOk());
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());

            // Signed in, sees nothing of the project: the same 404 as a project that does not exist.
            assertThat(detailOf(mvc.perform(authenticated(get("/api/v1/projects/" + project + "/report-plugins"),
                    asReader())).andExpect(status().isNotFound()).andReturn())).isEqualTo(PROJECT_NOT_FOUND);
            assertThat(detailOf(mvc.perform(authenticated(get("/api/v1/projects/" + (project + 100_000)
                    + "/report-plugins"), asReader())).andExpect(status().isNotFound()).andReturn()))
                    .isEqualTo(PROJECT_NOT_FOUND);
        }

        @Test
        @DisplayName("deleting the project takes its activations, in the same transaction")
        void projectDeleted() throws Exception {
            register(governor, manifest(IMAGE_A)).andExpect(status().isCreated());
            activate(asCiso(), project).andExpect(status().isOk());
            mvc.perform(authenticated(delete("/api/v1/projects/" + project), asAdmin())).andExpect(status().isNoContent());
            assertThat(jdbc.queryForObject("select count(*) from t_report_plugin_activation where project_id = ?",
                    Long.class, project)).isZero();
        }
    }

    @Nested
    @DisplayName("enabling")
    class Enabling {

        @Test
        @DisplayName("is the governor's; repeating it records nothing")
        void enabling() throws Exception {
            register(governor, manifest(IMAGE_A)).andExpect(status().isCreated());
            mvc.perform(authenticated(put("/api/v1/report-plugins/summary/enabled"), asAdmin())
                    .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\": false}")).andExpect(status().isForbidden());
            for (int i = 0; i < 2; i++) {
                mvc.perform(authenticated(put("/api/v1/report-plugins/summary/enabled"), governor)
                                .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\": false}"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.enabled").value(false));
            }
            mvc.perform(authenticated(put("/api/v1/report-plugins/summary/enabled"), governor)
                    .contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isBadRequest());
            assertThat(entries(AuditOperation.REPORT_PLUGIN_ENABLED_CHANGED)).hasSize(1);
        }
    }

    @Test
    @DisplayName("every gesture on the registry is queued for the SIEM as VECTI-SEC-031")
    void signalled() throws Exception {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_UDP", "endpoint": "127.0.0.1:9", "minSeverity": "LOW"}"""))
                .andExpect(status().isOk());
        outbox.deleteAll();
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");

        String digest = newest(body(register(governor, manifest(IMAGE_A))));
        approve(asCiso(), digest).andExpect(status().isOk());
        activate(asCiso(), project).andExpect(status().isOk());
        withdraw(governor, digest, "The renderer dropped accepted issues from the summary sheet.")
                .andExpect(status().isOk());

        List<JsonNode> queued = outbox.findAll().stream()
                .filter(row -> SiemEvents.TYPE.equals(row.getMessageType()))
                .map(row -> {
                    try {
                        return json.readTree(row.getPayload());
                    } catch (Exception unreadable) {
                        throw new IllegalStateException(unreadable);
                    }
                })
                .filter(event -> event.get("eventType").asText().equals("REPORT_PLUGIN_CHANGED"))
                .toList();
        assertThat(queued).extracting(event -> event.at("/extensions/act").asText()).containsExactlyInAnyOrder(
                "REPORT_PLUGIN_REGISTERED", "REPORT_PLUGIN_APPROVED", "REPORT_PLUGIN_ACTIVATED", "REPORT_PLUGIN_WITHDRAWN");
    }

    private static String statusOf(JsonNode plugin, String digest) {
        for (JsonNode manifest : plugin.at("/manifests")) {
            if (manifest.at("/digest").asText().equals(digest)) {
                return manifest.at("/status").asText();
            }
        }
        throw new AssertionError("no manifest " + digest);
    }
}
