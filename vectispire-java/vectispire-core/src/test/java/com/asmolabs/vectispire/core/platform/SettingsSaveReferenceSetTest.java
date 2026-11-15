package com.asmolabs.vectispire.core.platform;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.access.TriageApprovers;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.ai.AiReviewService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.notifications.NotificationDestinations;
import com.asmolabs.vectispire.core.notifications.NotificationService;
import com.asmolabs.vectispire.core.access.TeamChannels;
import com.asmolabs.vectispire.core.outbound.OutboundPost;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.tickets.TicketService;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * What a settings save answers, for the Rust port of {@code platform}'s second stage:
 * {@code vectispire-rust/reference/platform/settings-save.json}.
 *
 * <p><b>The save's rules, input by input, through the two seams the port fills itself.</b> The Rust side serves
 * {@code PUT /api/v1/settings} with {@code access}' approvers wired, and with two narrow parts of modules it has not
 * ported: {@code tickets}' reading of a pasted CA ({@link TicketService#caToPin}) and {@code ai}'s destination guard
 * ({@link AiReviewService#requireLocalUnlessAcknowledged}, the acknowledgement it stamps and erases). Here both run as
 * Java runs them — the CA through {@link PinnedCa#parsePasted} with the tracker's subject, the guard through a real
 * {@link AiReviewService} over a real {@link OutboundUrlGuard} — so the reference holds the seams' answers and not a
 * stand-in's. The resolver is a fixed table, recorded in the file, so no answer depends on a DNS server.
 *
 * <p>Each case runs the real {@link SettingsAdministrationService} over an in-memory settings store, and is recorded
 * with either the refusal — its status as {@code ApiExceptionHandler} maps the exception, its message, and the
 * integration a 409 names — or the answer and the audit entry; with both, every stored row afterwards, so a refusal
 * that wrote something shows. The Rust side ({@code cp-platform/tests/save_reference.rs}) puts the same rows and
 * switches in a real database, calls its service with the binary's seams, and reads the same things back.
 */
class SettingsSaveReferenceSetTest {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;
    private static final Instant NOW = Instant.parse("2026-11-15T12:34:56.789Z");
    private static final RequestActor ACTOR = new RequestActor("admin", "203.0.113.7", "reference");
    private static final String WRITER = "  lead\t";

    /** Every name the guard may be asked about; anything else does not resolve. */
    private static final Map<String, String> RESOLVER = new TreeMap<>(Map.of(
            "localhost", "7f000001",
            "model.corp", "0a010203",
            "llm.example.com", "5db8d822",
            "api.openai.com", "68120001"));

    @Test
    void whatASaveAnswers() {
        ArrayNode cases = NODES.arrayNode();
        shapes(cases);
        roles(cases);
        fourEyes(cases);
        trackers(cases);
        destinations(cases);
        channels(cases);
        ObjectNode out = RustReference.object();
        out.put("now", NOW.toString());
        ObjectNode resolver = NODES.objectNode();
        RESOLVER.forEach(resolver::put);
        out.set("resolver", resolver);
        out.set("cases", cases);
        RustReference.expect("platform/settings-save.json", out, SettingsSaveReferenceSetTest.class);
    }

    // ---------------------------------------------------------------------------------------------------------
    // The body and the values

    private static void shapes(ArrayNode cases) {
        save(cases, new Case("empty-body", "ADMIN"));
        save(cases, new Case("unknown-key", "ADMIN").body("no_such_setting", "1"));
        save(cases, new Case("unknown-key-after-a-valid-one", "ADMIN").body("sla_low_days", "90")
                .body("no_such_setting", "1"));
        save(cases, new Case("a-number", "ADMIN").body("sla_critical_days", "7"));
        // `String.trim` removes what is at or below U+0020, control characters included, and nothing else.
        save(cases, new Case("a-number-padded-with-controls", "ADMIN").body("sla_high_days", " \u0001 14\t\u0000"));
        save(cases, new Case("a-number-padded-with-a-no-break-space", "ADMIN").body("sla_high_days", " 30"));
        save(cases, new Case("not-a-number", "ADMIN").body("sla_critical_days", "seven"));
        save(cases, new Case("a-null-clears", "ADMIN").prior("notification_mail_to", "soc@example.org")
                .body("notification_mail_to", null));
        save(cases, new Case("several-in-their-order", "ADMIN").body("sla_low_days", "120")
                .body("eol_warn_days", "60").body("sast_enabled", "false"));
        save(cases, new Case("a-refusal-after-valid-ones-writes-nothing", "ADMIN").body("sla_low_days", "120")
                .body("sla_critical_days", "-1"));
        save(cases, new Case("the-acknowledgement-by-from-the-wire", "SUPERUSER")
                .body("ai_review_risk_acknowledged_by", "someone"));
        save(cases, new Case("the-acknowledgement-at-from-the-wire", "SUPERUSER")
                .body("ai_review_risk_acknowledged_at", NOW.toString()));
        save(cases, new Case("a-credential-through-this-door", "ADMIN").body("ticket_token", "glpat-abc"));
        save(cases, new Case("a-secret-is-described-without-its-value", "ADMIN")
                .body("notification_slack_url", "https://hooks.example.com/T1/B2"));
        save(cases, new Case("a-secret-cleared", "ADMIN").prior("notification_slack_url", "https://hooks.example.com/x")
                .body("notification_slack_url", ""));
        save(cases, new Case("expiry-a-date", "ADMIN").body("ticket_token_expires_on", "2027-01-31"));
        save(cases, new Case("expiry-not-a-day-of-the-calendar", "ADMIN").body("ticket_token_expires_on", "2027-02-30"));
        save(cases, new Case("expiry-cleared", "ADMIN").body("ticket_token_expires_on", "  "));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Who may change what

    private static void roles(ArrayNode cases) {
        String visibility = Setting.TARGET_VISIBILITY.defaultValue();
        save(cases, new Case("a-rule-by-an-administrator", "ADMIN").body("target_visibility", visibility));
        save(cases, new Case("a-rule-by-the-governor", "SUPERUSER").body("target_visibility", visibility));
        save(cases, new Case("a-rule-by-nobody", null).body("target_visibility", visibility));
        save(cases, new Case("evidence-window-by-a-ciso", "CISO").body("evidence_retention_days", "400"));
        save(cases, new Case("tracker-url-changed-by-a-ciso", "CISO").body("ticket_base_url", "https://jira.corp"));
        // Secret, so refused whatever it holds: an unchanged value is not told apart from a changed one.
        save(cases, new Case("tracker-url-unchanged-by-a-ciso", "CISO").prior("ticket_base_url", "https://jira.corp")
                .body("ticket_base_url", "https://jira.corp"));
        save(cases, new Case("tracker-project-unchanged-by-a-ciso", "CISO").prior("ticket_project", "SEC")
                .body("ticket_project", "SEC"));
        save(cases, new Case("tracker-project-changed-by-a-ciso", "CISO").prior("ticket_project", "SEC")
                .body("ticket_project", "OPS"));
        save(cases, new Case("openai-url-changed-by-a-ciso", "CISO").body("ai_review_openai_url", "https://x.corp/v1"));
        save(cases, new Case("expiry-changed-by-a-ciso", "CISO").body("ticket_token_expires_on", "2027-01-31"));
        save(cases, new Case("ollama-url-changed-by-a-ciso", "CISO").body("ai_review_ollama_url", "http://model.corp"));
        save(cases, new Case("siem-reach-changed-by-a-ciso", "CISO").body("siem_allow_private_destination", "true"));
        save(cases, new Case("siem-reach-unchanged-by-a-ciso", "CISO").body("siem_allow_private_destination",
                Setting.SIEM_ALLOW_PRIVATE_DESTINATION.defaultValue()));
        save(cases, new Case("siem-reach-padded-by-a-ciso", "CISO").body("siem_allow_private_destination",
                " " + Setting.SIEM_ALLOW_PRIVATE_DESTINATION.defaultValue() + " "));
        save(cases, new Case("siem-reach-changed-by-nobody", null).body("siem_allow_private_destination", "true"));
        save(cases, new Case("a-parameter-by-a-champion", "SECURITY_CHAMPION").body("sla_low_days", "100"));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Four-eyes

    private static void fourEyes(ArrayNode cases) {
        save(cases, new Case("four-eyes-on", "SUPERUSER").body("triage_four_eyes_required", "true"));
        save(cases, new Case("four-eyes-on-upper-case", "SUPERUSER").body("triage_four_eyes_required", "TRUE"));
        save(cases, new Case("four-eyes-off", "SUPERUSER").prior("triage_four_eyes_required", "true")
                .body("triage_four_eyes_required", "false"));
        save(cases, new Case("four-eyes-on-without-an-approver", "SUPERUSER").people(false, true, true)
                .body("triage_four_eyes_required", "true"));
        save(cases, new Case("four-eyes-on-without-two-publishers", "SUPERUSER").people(true, false, true)
                .body("triage_four_eyes_required", "true"));
        save(cases, new Case("four-eyes-on-without-two-signers", "SUPERUSER").people(true, true, false)
                .body("triage_four_eyes_required", "true"));
        save(cases, new Case("four-eyes-off-without-anybody", "SUPERUSER").people(false, false, false)
                .body("triage_four_eyes_required", "false"));
        save(cases, new Case("four-eyes-on-by-an-administrator", "ADMIN").people(false, false, false)
                .body("triage_four_eyes_required", "true"));
    }

    // ---------------------------------------------------------------------------------------------------------
    // The tracker: its CA, its integration, its project

    private static void trackers(ArrayNode cases) {
        String root = pem("01-root.pem");
        String leaf = pem("03-leaf.pem");
        save(cases, new Case("ca-a-root", "ADMIN").body("ticket_ca_pem", root));
        save(cases, new Case("ca-a-leaf", "ADMIN").body("ticket_ca_pem", leaf));
        save(cases, new Case("ca-expired", "ADMIN").body("ticket_ca_pem", pem("05-expired.pem")));
        save(cases, new Case("ca-not-yet-valid", "ADMIN").body("ticket_ca_pem", pem("06-future.pem")));
        save(cases, new Case("ca-not-a-pem", "ADMIN").body("ticket_ca_pem", "not a certificate"));
        save(cases, new Case("ca-a-leaf-unchanged", "ADMIN").prior("ticket_ca_pem", leaf).body("ticket_ca_pem", leaf));
        save(cases, new Case("ca-a-leaf-unchanged-but-padded", "ADMIN").prior("ticket_ca_pem", "\n" + leaf + "\n")
                .body("ticket_ca_pem", leaf));
        save(cases, new Case("ca-cleared", "ADMIN").prior("ticket_ca_pem", root).body("ticket_ca_pem", ""));

        save(cases, new Case("tracker-chosen", "ADMIN").body("ticket_provider", "jira"));
        save(cases, new Case("tracker-chosen-disabled", "ADMIN").disabled("tracker.jira").body("ticket_provider", "jira"));
        save(cases, new Case("tracker-chosen-disabled-in-capitals", "ADMIN").disabled("tracker.jira")
                .body("ticket_provider", " JIRA "));
        save(cases, new Case("tracker-unchanged-disabled", "ADMIN").disabled("tracker.jira").prior("ticket_provider", "jira")
                .body("ticket_provider", "jira").body("ticket_labels", "vectispire"));
        save(cases, new Case("tracker-none-whatever-is-disabled", "ADMIN").disabled("tracker.jira", "tracker.github")
                .prior("ticket_provider", "jira").body("ticket_provider", "none"));

        save(cases, new Case("github-project-two-names", "ADMIN").body("ticket_provider", "github")
                .body("ticket_project", "owner/repository"));
        save(cases, new Case("github-project-dot-dot", "ADMIN").body("ticket_provider", "github")
                .body("ticket_project", "owner/.."));
        save(cases, new Case("github-project-one-name", "ADMIN").prior("ticket_provider", "github")
                .body("ticket_project", "repository"));
        save(cases, new Case("github-chosen-over-a-project-of-one-name", "ADMIN").prior("ticket_project", "SEC")
                .body("ticket_provider", "github"));
        save(cases, new Case("github-project-stored-before-the-check", "ADMIN").prior("ticket_provider", "github")
                .prior("ticket_project", "SEC").body("ticket_labels", "a"));
        save(cases, new Case("jira-project-of-one-name", "ADMIN").body("ticket_provider", "jira")
                .body("ticket_project", "SEC"));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Where the code reviewed is sent

    private static void destinations(ArrayNode cases) {
        save(cases, new Case("ollama-internal", "ADMIN").body("ai_review_ollama_url", "http://model.corp:11434"));
        save(cases, new Case("ollama-public", "ADMIN").body("ai_review_ollama_url", "http://llm.example.com:11434"));
        save(cases, new Case("ollama-unresolvable", "ADMIN").body("ai_review_ollama_url", "http://nowhere.corp"));
        save(cases, new Case("ollama-cleared-reads-the-default", "ADMIN")
                .prior("ai_review_ollama_url", "http://model.corp").body("ai_review_ollama_url", ""));
        save(cases, new Case("ollama-public-acknowledged", "ADMIN").body("ai_review_ollama_url", "http://llm.example.com")
                .body("ai_review_allow_remote_url", "true"));
        save(cases, new Case("ollama-public-stored-unrelated-save", "ADMIN")
                .prior("ai_review_ollama_url", "http://llm.example.com").body("sla_low_days", "100"));
        save(cases, new Case("openai-chosen-unacknowledged", "ADMIN").body("ai_review_provider", "openai"));
        save(cases, new Case("openai-chosen-in-capitals-unacknowledged", "ADMIN").body("ai_review_provider", " OpenAI "));
        save(cases, new Case("openai-chosen-acknowledged", "ADMIN").body("ai_review_provider", "openai")
                .body("ai_review_allow_remote_url", "true"));
        save(cases, new Case("openai-internal-url", "ADMIN").body("ai_review_provider", "openai")
                .body("ai_review_openai_url", "http://model.corp/v1"));
        save(cases, new Case("openai-stored-acknowledged-unrelated-save", "ADMIN").prior("ai_review_provider", "openai")
                .prior("ai_review_allow_remote_url", "true").prior("ai_review_risk_acknowledged_by", "first")
                .prior("ai_review_risk_acknowledged_at", "2026-01-01T00:00:00Z").body("ai_review_model", "gpt-4o"));
        save(cases, new Case("acknowledgement-sent-back-on", "ADMIN").prior("ai_review_allow_remote_url", "true")
                .prior("ai_review_risk_acknowledged_by", "first").prior("ai_review_risk_acknowledged_at", "2026-01-01T00:00:00Z")
                .body("ai_review_allow_remote_url", "true"));
        save(cases, new Case("acknowledgement-withdrawn-over-openai", "ADMIN").prior("ai_review_provider", "openai")
                .prior("ai_review_allow_remote_url", "true").prior("ai_review_risk_acknowledged_by", "first")
                .prior("ai_review_risk_acknowledged_at", "2026-01-01T00:00:00Z").body("ai_review_allow_remote_url", "false"));
        save(cases, new Case("acknowledgement-off-sent-unchanged-over-openai", "ADMIN").prior("ai_review_provider", "openai")
                .body("ai_review_allow_remote_url", "false"));
        save(cases, new Case("openai-chosen-disabled", "ADMIN").disabled("ai.openai").body("ai_review_provider", "openai")
                .body("ai_review_allow_remote_url", "true"));
        save(cases, new Case("openai-unchanged-disabled", "ADMIN").disabled("ai.openai").prior("ai_review_provider", "openai")
                .prior("ai_review_allow_remote_url", "true").body("ai_review_provider", "openai"));
        save(cases, new Case("review-on-over-a-disabled-ollama", "ADMIN").disabled("ai.ollama")
                .body("ai_review_enabled", "true"));
        save(cases, new Case("review-on-already-over-a-disabled-ollama", "ADMIN").disabled("ai.ollama")
                .prior("ai_review_enabled", "true").body("ai_review_enabled", "true"));
    }

    // ---------------------------------------------------------------------------------------------------------
    // The notification channels a save configures

    private static void channels(ArrayNode cases) {
        save(cases, new Case("slack-configured-disabled", "ADMIN").disabled("notification.slack")
                .body("notification_slack_url", "https://hooks.example.com/T1"));
        save(cases, new Case("slack-cleared-disabled", "ADMIN").disabled("notification.slack")
                .prior("notification_slack_url", "https://hooks.example.com/T1").body("notification_slack_url", ""));
        save(cases, new Case("teams-switched-on-disabled", "ADMIN").disabled("notification.teams")
                .body("notification_teams_enabled", "true"));
        save(cases, new Case("teams-switched-off-disabled", "ADMIN").disabled("notification.teams")
                .prior("notification_teams_enabled", "true").body("notification_teams_enabled", "false"));
        save(cases, new Case("mail-recipients-unchanged-disabled", "ADMIN").disabled("notification.mail")
                .prior("notification_mail_to", "soc@example.org").body("notification_mail_to", " soc@example.org "));
        save(cases, new Case("reminders-on-over-a-disabled-mail", "SUPERUSER").disabled("notification.mail")
                .body("checklist_reminders_enabled", "true"));
        save(cases, new Case("two-channels-the-second-disabled", "ADMIN").disabled("notification.discord")
                .body("notification_webhook_url", "https://hooks.example.com/a")
                .body("notification_discord_url", "https://hooks.example.com/b"));
    }

    // ---------------------------------------------------------------------------------------------------------

    /** One save: the writer's role, the rows before it, the switches off, the approvers, and the body in its order. */
    private static final class Case {
        final String name;
        final String role;
        final Map<String, String> prior = new TreeMap<>();
        final List<String> disabled = new ArrayList<>();
        final Map<String, String> body = new LinkedHashMap<>();
        boolean approver = true;
        boolean publishers = true;
        boolean signers = true;

        Case(String name, String role) {
            this.name = name;
            this.role = role;
        }

        Case prior(String key, String value) {
            prior.put(key, value);
            return this;
        }

        Case body(String key, String value) {
            body.put(key, value);
            return this;
        }

        Case disabled(String... keys) {
            disabled.addAll(List.of(keys));
            return this;
        }

        Case people(boolean approver, boolean publishers, boolean signers) {
            this.approver = approver;
            this.publishers = publishers;
            this.signers = signers;
            return this;
        }
    }

    private static void save(ArrayNode cases, Case input) {
        Map<String, String> rows = new TreeMap<>(input.prior);
        SettingsService settings = mock(SettingsService.class);
        when(settings.get(any())).thenAnswer(invocation -> {
            Setting setting = invocation.getArgument(0);
            return rows.getOrDefault(setting.key(), setting.defaultValue());
        });
        when(settings.isEnabled(any())).thenAnswer(invocation -> {
            Setting setting = invocation.getArgument(0);
            return "true".equals(rows.getOrDefault(setting.key(), setting.defaultValue()));
        });
        when(settings.stored()).thenAnswer(invocation -> Map.copyOf(rows));
        doAnswer(invocation -> {
            Setting setting = invocation.getArgument(0);
            rows.put(setting.key(), invocation.getArgument(1));
            return null;
        }).when(settings).set(any(), anyString());

        Set<String> off = Set.copyOf(input.disabled);
        Integrations integrations = mock(Integrations.class);
        doAnswer(invocation -> {
            Integration integration = invocation.getArgument(0);
            if (off.contains(integration.key())) {
                throw new IntegrationDisabledException(integration);
            }
            return null;
        }).when(integrations).requireEnabled(any());
        doAnswer(invocation -> {
            Integration integration = invocation.getArgument(0);
            if (off.contains(integration.key())) {
                throw new IntegrationDisabledException(integration);
            }
            return null;
        }).when(integrations).holdEnabled(any());

        TriageApprovers approvers = mock(TriageApprovers.class);
        when(approvers.anyActive()).thenReturn(input.approver);
        when(approvers.twoCanPublishTemplates()).thenReturn(input.publishers);
        when(approvers.twoCanSignOffChecklists()).thenReturn(input.signers);

        // `tickets`' part of the save, as `TicketService.caToPin` reads it.
        TicketService tickets = mock(TicketService.class);
        when(tickets.caToPin(anyString())).thenAnswer(invocation -> {
            String pem = invocation.getArgument(0);
            return pem == null || pem.isBlank()
                    ? Optional.empty()
                    : Optional.of(PinnedCa.parsePasted(pem, NOW, TicketService.CA));
        });

        // `ai`'s part of the save, as it runs: the real service, its guard over the fixed resolver.
        OutboundUrlGuard guard = new OutboundUrlGuard(hostname -> {
            String hex = RESOLVER.get(hostname.toLowerCase(java.util.Locale.ROOT));
            return hex == null ? List.of() : List.of(HexFormat.of().parseHex(hex));
        });
        AiReviewService ai = new AiReviewService(
                settings, null, new OutboundPost(null, guard, null), null, null, integrations);

        AuditLogService audit = mock(AuditLogService.class);
        List<AuditLogService.Record> entries = new ArrayList<>();
        doAnswer(invocation -> {
            entries.add(invocation.getArgument(0));
            return null;
        }).when(audit).record(any(AuditLogService.Record.class));
        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        SettingsAdministrationService service = new SettingsAdministrationService(
                settings,
                ai,
                approvers,
                tickets,
                mock(NotificationService.class),
                audit,
                integrations,
                new NotificationDestinations(settings, mock(TeamChannels.class)),
                new TransactionTemplate(manager),
                Clock.fixed(NOW, ZoneOffset.UTC));

        ObjectNode recorded = NODES.objectNode();
        recorded.put("name", input.name);
        recorded.put("role", input.role);
        ObjectNode prior = NODES.objectNode();
        input.prior.forEach(prior::put);
        recorded.set("prior", prior);
        ArrayNode disabled = NODES.arrayNode();
        input.disabled.forEach(disabled::add);
        recorded.set("disabled", disabled);
        ObjectNode people = NODES.objectNode();
        people.put("approver", input.approver);
        people.put("publishers", input.publishers);
        people.put("signers", input.signers);
        recorded.set("people", people);
        // An array of pairs, not an object: the order is the audit entry's, and a value may be null.
        ArrayNode body = NODES.arrayNode();
        input.body.forEach((key, value) -> body.add(NODES.arrayNode().add(key).add(value)));
        recorded.set("body", body);

        Optional<UserView> writer = Optional.ofNullable(input.role).map(role -> new UserView(
                1L, WRITER, null, null, null, role, true, null, null, NOW, NOW, false, false, false));
        ObjectNode outcome = NODES.objectNode();
        try {
            SettingsAdministrationService.Applied applied = service.update(input.body, writer, ACTOR);
            outcome.put("updated", applied.count());
        } catch (InvalidInputException refused) {
            outcome.set("refused", refusal(400, refused.getMessage(), null));
        } catch (AccessDeniedException refused) {
            outcome.set("refused", refusal(403, refused.getMessage(), null));
        } catch (IntegrationDisabledException refused) {
            outcome.set("refused", refusal(409, refused.getMessage(), refused.integration().key()));
        } catch (UnsafeUrlException refused) {
            outcome.set("refused", refusal(422, refused.getMessage(), null));
        }
        ArrayNode audited = NODES.arrayNode();
        for (AuditLogService.Record entry : entries) {
            ObjectNode line = NODES.objectNode();
            line.put("operation", entry.operation().name());
            line.put("resourceId", entry.resourceId());
            line.put("description", entry.description());
            line.put("userId", entry.userId());
            line.put("signal", entry.signal() == null ? null : entry.signal().name());
            audited.add(line);
        }
        outcome.set("audit", audited);
        ObjectNode stored = NODES.objectNode();
        rows.forEach(stored::put);
        outcome.set("stored", stored);
        recorded.set("outcome", outcome);
        cases.add(recorded);
    }

    private static ObjectNode refusal(int status, String detail, String integration) {
        ObjectNode refused = NODES.objectNode();
        refused.put("status", status);
        refused.put("detail", detail);
        refused.put("integration", integration);
        return refused;
    }

    /** A CA of the SIEM's reference set: the tracker's is read by the same rule, in its own words. */
    private static String pem(String name) {
        Path file = Path.of(System.getProperty("vectispire.rust.reference"), "siem", "collector-ca", name);
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }
}
