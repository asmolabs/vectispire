package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationInUseException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.notifications.NotificationChannelKind;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.persistence.TeamEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamWebhookEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamWebhookRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.issues.ScanDelta;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.maintenance.internal.MaintenanceJobs;
import com.asmolabs.vectispire.core.notifications.internal.ScanDeltaNotifier;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageEntity;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.platform.SettingsAdministrationService;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The notification channels as integrations (decision 0040, lot I6), through the real routes, registry, outbox and
 * database: a channel with a destination — wherever it is configured — cannot be switched off; one without can, and
 * is then neither configured, nor listed, nor tested, nor sent to; and a row for a channel switched off by hand waits
 * in the outbox rather than being sent or lost.
 *
 * <p>What a channel receives is read at a fake receiver on the loopback, beside a case where it does receive — or
 * "nothing arrived" could be a receiver that never listens. {@code t_integration} is not emptied between tests; each
 * case puts its rows back ({@link IntegrationRows}). The two races are forced with latches.
 */
@DisplayName("notification channels as integrations, through the routes")
class NotificationChannelSwitchRoutesTest extends ApiTestBase {

    private static final String IN_USE = "urn:vectispire:problem:integration-in-use";
    private static final String DISABLED = "urn:vectispire:problem:integration-disabled";
    private static final Integration WEBHOOK = Integration.of(NotificationChannelKind.WEBHOOK);
    private static final Integration TEAMS = Integration.of(NotificationChannelKind.TEAMS);
    private static final Integration SLACK = Integration.of(NotificationChannelKind.SLACK);
    private static final Integration MAIL = Integration.of(NotificationChannelKind.MAIL);

    @Autowired
    private Integrations integrations;

    @Autowired
    private SettingsService settings;

    @Autowired
    private SettingsAdministrationService administration;

    @Autowired
    private ScanDeltaNotifier notifier;

    @Autowired
    private MaintenanceJobs jobs;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private TeamRepository teams;

    @Autowired
    private TeamWebhookRepository teamWebhooks;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    private IntegrationRows rows;
    private ExecutorService threads;
    private HttpServer receiver;
    private final List<String> received = new CopyOnWriteArrayList<>();
    private String hook;

    @BeforeEach
    void receiverOnTheLoopback() throws Exception {
        rows = IntegrationRows.remember(jdbc);
        threads = Executors.newFixedThreadPool(2);
        receiver = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        receiver.createContext("/", exchange -> {
            received.add(exchange.getRequestURI().getPath() + " "
                    + new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        receiver.start();
        hook = "http://127.0.0.1:" + receiver.getAddress().getPort() + "/hook";
        settings.set(Setting.NOTIFICATION_ALLOW_PRIVATE_URL, "true");
    }

    @AfterEach
    void putBack() throws Exception {
        threads.shutdownNow();
        assertThat(threads.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        receiver.stop(0);
        rows.putBack();
    }

    @Test
    @DisplayName("a channel with a destination, wherever it is configured, is not switched off: 409 integration-in-use naming it, nothing changed, nothing audited")
    void aChannelInUseIsNotSwitchedOff() throws Exception {
        record Use(Integration channel, String says, Runnable configure, Runnable clear) {}
        long team = team("in-use-" + System.nanoTime());
        List<Use> uses = List.of(
                new Use(WEBHOOK, "the global webhook URL is set",
                        () -> settings.set(Setting.WEBHOOK_URL, hook), () -> settings.set(Setting.WEBHOOK_URL, "")),
                new Use(WEBHOOK, "a team has a webhook of its own",
                        () -> teamWebhooks.save(new TeamWebhookEntity(team, hook)), () -> teamWebhooks.deleteById(team)),
                new Use(TEAMS, "the Microsoft Teams URL is set",
                        () -> settings.set(Setting.TEAMS_WEBHOOK_URL, hook), () -> settings.set(Setting.TEAMS_WEBHOOK_URL, "")),
                new Use(SLACK, "the Slack URL is set",
                        () -> settings.set(Setting.SLACK_WEBHOOK_URL, hook), () -> settings.set(Setting.SLACK_WEBHOOK_URL, "")),
                new Use(Integration.of(NotificationChannelKind.DISCORD), "the Discord URL is set",
                        () -> settings.set(Setting.DISCORD_WEBHOOK_URL, hook),
                        () -> settings.set(Setting.DISCORD_WEBHOOK_URL, "")),
                new Use(MAIL, "e-mail recipients are set",
                        () -> settings.set(Setting.MAIL_RECIPIENTS, "secops@example.com"),
                        () -> settings.set(Setting.MAIL_RECIPIENTS, "")),
                new Use(MAIL, "the weekly checklist reminders are on",
                        () -> settings.set(Setting.CHECKLIST_REMINDERS_ENABLED, "true"),
                        () -> settings.set(Setting.CHECKLIST_REMINDERS_ENABLED, "false")));

        for (Use use : uses) {
            use.configure().run();
            Map<String, Object> before = row(use.channel());
            ResultActions refused = governorSwitches(use.channel(), false).andExpect(status().isConflict())
                    .andExpect(jsonPath("$.type").value(IN_USE))
                    .andExpect(jsonPath("$.integration").value(use.channel().key()));
            assertThat(detailOf(refused.andReturn())).as(use.says())
                    .startsWith("The integration \"" + use.channel().key() + "\" is in use and cannot be disabled")
                    .contains(use.says())
                    .contains("lost in silence");
            assertThat(integrations.isEnabled(use.channel())).isTrue();
            assertThat(row(use.channel())).as("not touched: " + use.says()).isEqualTo(before);

            // Emptied, it goes; and back on for the next use.
            use.clear().run();
            governorSwitches(use.channel(), false).andExpect(status().isOk()).andExpect(jsonPath("$.enabled").value(false));
            governorSwitches(use.channel(), true).andExpect(status().isOk());
        }
        // Teams needs its own switch as well as its URL to send: the URL alone, switched off, is no use.
        settings.set(Setting.TEAMS_WEBHOOK_URL, hook);
        settings.set(Setting.TEAMS_ENABLED, "false");
        governorSwitches(TEAMS, false).andExpect(status().isOk());

        // Two audited per use (off, on), one for Teams; none for a refusal.
        assertThat(switchesAudited()).isEqualTo(2L * uses.size() + 1);
    }

    @Test
    @DisplayName("a channel switched off is not configured: 409 integration-disabled on a URL, recipients, a switch or a team's webhook, nothing written; emptying is always saved")
    void aDisabledChannelIsNotConfigured() throws Exception {
        governorSwitches(SLACK, false).andExpect(status().isOk());
        governorSwitches(MAIL, false).andExpect(status().isOk());
        governorSwitches(WEBHOOK, false).andExpect(status().isOk());

        ResultActions refused = save(Map.of(Setting.SLACK_WEBHOOK_URL.key(), hook)).andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(DISABLED))
                .andExpect(jsonPath("$.integration").value("notification.slack"));
        assertThat(detailOf(refused.andReturn())).contains("\"notification.slack\" is disabled");
        assertThat(settings.get(Setting.SLACK_WEBHOOK_URL)).isEmpty();

        // Nothing of the save is written, its other settings included.
        save(Map.of(Setting.NOTIFICATION_MIN_SEVERITY.key(), "critical", Setting.MAIL_RECIPIENTS.key(), "a@example.com"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.integration").value("notification.mail"));
        assertThat(settings.get(Setting.NOTIFICATION_MIN_SEVERITY)).isNotEqualTo("critical");
        save(Map.of(Setting.CHECKLIST_REMINDERS_ENABLED.key(), "true")).andExpect(status().isConflict())
                .andExpect(jsonPath("$.integration").value("notification.mail"));

        long team = team("disabled-" + System.nanoTime());
        mvc.perform(authenticated(put("/api/v1/teams/" + team + "/webhook"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("url", hook))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(DISABLED))
                .andExpect(jsonPath("$.integration").value("notification.webhook"));
        assertThat(teamWebhooks.existsById(team)).isFalse();

        // Emptying, and sending the stored values back, configure nothing and are saved.
        save(Map.of(Setting.SLACK_WEBHOOK_URL.key(), "", Setting.CHECKLIST_REMINDERS_ENABLED.key(), "false",
                Setting.MAIL_RECIPIENTS.key(), "")).andExpect(status().isOk());
        mvc.perform(authenticated(put("/api/v1/teams/" + team + "/webhook"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("url", ""))))
                .andExpect(status().isOk());

        // On again, the same save goes through.
        governorSwitches(SLACK, true).andExpect(status().isOk());
        save(Map.of(Setting.SLACK_WEBHOOK_URL.key(), hook)).andExpect(status().isOk());
        assertThat(settings.get(Setting.SLACK_WEBHOOK_URL)).isEqualTo(hook);
    }

    @Test
    @DisplayName("a channel switched off is absent from the channels' list, and its test is refused 409 before anything is sent")
    void aDisabledChannelIsNeitherListedNorTested() throws Exception {
        settings.set(Setting.SLACK_WEBHOOK_URL, hook);
        mvc.perform(authenticated(post("/api/v1/notifications/test/slack"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        assertThat(received).as("the receiver does listen").hasSize(1);
        received.clear();

        // Past the in-use refusal, as a row written by hand would be.
        jdbc.update("update t_integration set enabled = ? where integration_key = ?", false, SLACK.key());

        String listed = mvc.perform(authenticated(get("/api/v1/notifications/channels"), asAdmin()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(listed).findValuesAsText("type")).doesNotContain("scan_delta_slack")
                .contains("scan_delta", "scan_delta_teams");
        mvc.perform(authenticated(post("/api/v1/notifications/test/slack"), asAdmin()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(DISABLED))
                .andExpect(jsonPath("$.integration").value("notification.slack"));
        assertThat(received).isEmpty();
    }

    @Test
    @DisplayName("a scan's delta queued for a channel switched off by hand is held — pending, uncounted — never sent, and leaves once it is on; nothing new is queued for it")
    void theSenderNeverCallsADisabledChannel() throws Exception {
        settings.set(Setting.WEBHOOK_URL, hook);
        long repository = repository();
        outbox.deleteAll();
        enqueueDelta(repository);
        assertThat(webhookRows()).hasSize(1);
        jdbc.update("update t_integration set enabled = ? where integration_key = ?", false, WEBHOOK.key());

        jobs.relayNotifications();
        OutboxMessageEntity held = webhookRows().getFirst();
        assertThat(held.getStatus()).isEqualTo("pending");
        assertThat(held.getAttempts()).as("no attempt counted").isZero();
        assertThat(held.getLastError()).contains("notification.webhook").contains("disabled").contains("waits");
        assertThat(received).as("nothing reached the disabled channel").isEmpty();

        // Nothing more is queued for it meanwhile.
        enqueueDelta(repository);
        assertThat(webhookRows()).hasSize(1);

        integrations.switchTo(WEBHOOK, true, "governor");
        outbox.recordAttempt(held.getId(), 0, held.getLastError(), "pending", null);
        jobs.relayNotifications();
        assertThat(received).singleElement().asString().startsWith("/hook ").contains("CVE-2026-0606");
        assertThat(outbox.findById(held.getId()).orElseThrow().getStatus()).isEqualTo("sent");
    }

    @Test
    @DisplayName("a scan's delta reaches a channel of its own with no webhook configured — the webhook alone decided whether one was built")
    void aDeltaReachesAChannelWithoutAWebhook() throws Exception {
        long repository = repository();
        outbox.deleteAll();
        enqueueDelta(repository);
        assertThat(outbox.findAll()).as("no destination, nothing queued").isEmpty();

        settings.set(Setting.SLACK_WEBHOOK_URL, hook);
        enqueueDelta(repository);
        assertThat(outbox.findAll()).extracting(OutboxMessageEntity::getMessageType).containsExactly("scan_delta_slack");
    }

    @Test
    @DisplayName("a switch arriving while a save holds the channel waits for it, then sees it in use")
    void aSwitchWaitsForTheSaveThatHoldsTheChannel() throws Exception {
        CountDownLatch holding = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        // The save's transaction, stopped between taking the channel and writing the URL that uses it.
        Future<?> saving = threads.submit(() -> transactions.executeWithoutResult(status -> {
            integrations.holdEnabled(SLACK);
            holding.countDown();
            await(release);
            settings.set(Setting.SLACK_WEBHOOK_URL, hook);
        }));
        assertThat(holding.await(10, TimeUnit.SECONDS)).isTrue();

        Future<Integrations.Switched> switching = threads.submit(() -> integrations.switchTo(SLACK, false, "governor"));
        assertThatThrownBy(() -> switching.get(1_000, TimeUnit.MILLISECONDS))
                .as("the switch waits for the save").isInstanceOf(TimeoutException.class);

        release.countDown();
        saving.get(30, TimeUnit.SECONDS);
        assertThatThrownBy(() -> switching.get(30, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class).hasCauseInstanceOf(IntegrationInUseException.class);
        assertThat(integrations.isEnabled(SLACK)).isTrue();
        assertThat(settings.get(Setting.SLACK_WEBHOOK_URL)).isEqualTo(hook);
    }

    @Test
    @DisplayName("a save arriving while a switch is still open waits for it, then reads the channel off: refused, nothing written")
    void aSaveWaitsForTheSwitch() throws Exception {
        CountDownLatch switched = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        // The governor's switch, done and not yet committed.
        Future<?> switching = threads.submit(() -> transactions.executeWithoutResult(status -> {
            assertThat(integrations.switchTo(SLACK, false, "governor").changed()).isTrue();
            switched.countDown();
            await(release);
        }));
        assertThat(switched.await(10, TimeUnit.SECONDS)).isTrue();

        Future<?> saving = threads.submit(() -> administration.update(
                Map.of(Setting.SLACK_WEBHOOK_URL.key(), hook), Optional.of(administrator()),
                new RequestActor("notification-switch-test", null, null)));
        assertThatThrownBy(() -> saving.get(1_000, TimeUnit.MILLISECONDS))
                .as("the save waits for the switch").isInstanceOf(TimeoutException.class);

        release.countDown();
        switching.get(30, TimeUnit.SECONDS);
        assertThatThrownBy(() -> saving.get(30, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class).hasCauseInstanceOf(IntegrationDisabledException.class);
        assertThat(integrations.isEnabled(SLACK)).isFalse();
        assertThat(settings.get(Setting.SLACK_WEBHOOK_URL)).isEmpty();
    }

    private void enqueueDelta(long repository) {
        IssueEntity issue = new IssueEntity();
        issue.setId(repository * 10);
        issue.setIdentifier("CVE-2026-0606");
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setSeverity(Severity.CRITICAL.wireName());
        issue.setState(IssueState.OPEN.wireName());
        transactions.executeWithoutResult(status -> notifier.enqueue(new ScanDelta(
                repository * 100, new ScanTarget.Repository(repository), List.of(IssueView.of(issue)), List.of(), 0)));
    }

    private List<OutboxMessageEntity> webhookRows() {
        return outbox.findAll().stream().filter(row -> "scan_delta".equals(row.getMessageType())).toList();
    }

    private long repository() {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("https://example.invalid/notified-" + System.nanoTime() + ".git");
        entity.setName("notified");
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private long team(String name) {
        TeamEntity team = new TeamEntity();
        team.setName(name);
        team.setCreatedAt(java.time.Instant.now());
        return teams.save(team).getId();
    }

    private static UserView administrator() {
        UserEntity user = new UserEntity();
        user.setUsername("notification-admin");
        user.setRole(Role.ADMIN.name());
        return UserView.of(user);
    }

    private ResultActions governorSwitches(Integration integration, boolean enabled) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/integrations/" + integration.key() + "/enabled"),
                        tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false))
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("enabled", enabled))));
    }

    private ResultActions save(Map<String, String> body) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private Map<String, Object> row(Integration integration) {
        return jdbc.queryForMap("select enabled, updated_at, updated_by from t_integration where integration_key = ?",
                integration.key());
    }

    private long switchesAudited() {
        return auditLog.findAll().stream()
                .filter(entry -> AuditOperation.INTEGRATION_ENABLED_CHANGED.wireName().equals(entry.getOperationType()))
                .count();
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(30, TimeUnit.SECONDS)) {
                throw new IllegalStateException("never released");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }
}
