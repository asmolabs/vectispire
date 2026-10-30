package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.tickets.TicketService;
import com.asmolabs.vectispire.core.tickets.internal.TicketSweepTask;
import com.asmolabs.vectispire.core.tickets.internal.TicketTokenCheckTask;
import com.asmolabs.vectispire.core.tickets.persistence.IssueTicketRepository;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;

/**
 * A GitLab tracker when the governor switches {@code tracker.gitlab} off (decision 0040 §3, lot I6), over HTTP and
 * through the maintenance tasks the tick runs, against a tracker on loopback behind its own CA: nothing reaches it,
 * no token leaves, a ticket attached by hand is refused 409 {@code integration-disabled}, and the tracker card reads
 * {@code suspended} — with the token and the settings kept, so that switching it back on resumes everything.
 *
 * <p>{@code t_integration} is put back as it was found after each case ({@link IntegrationRows}).
 */
@DisplayName("a tracker whose integration is disabled")
class TrackerSuspensionRoutesTest extends ApiTestBase {

    private static final String ISSUES = "/api/v4/projects/team%2Fservice/issues";
    private static final String SELF = "/api/v4/personal_access_tokens/self";
    private static final String DISABLED = "urn:vectispire:problem:integration-disabled";
    private static final Integration GITLAB = Integration.of(TicketProvider.GITLAB);

    @Autowired
    private Integrations integrations;

    @Autowired
    private SettingsService settings;

    @Autowired
    private TicketService tickets;

    @Autowired
    private TicketSweepTask sweep;

    @Autowired
    private TicketTokenCheckTask tokenCheck;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private IssueTicketRepository ticketLinks;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private JdbcTemplate jdbc;

    private IntegrationRows rows;
    private ForgeStub tracker;
    private long repositoryId;

    @BeforeEach
    void configured() throws Exception {
        rows = IntegrationRows.remember(jdbc);
        tracker = ForgeStub.start()
                .route(ISSUES, Reply.json("{\"iid\":7,\"web_url\":\"https://gitlab.internal/team/service/-/issues/7\"}"))
                .route(ISSUES + "/9", Reply.json("{}"))
                .route(SELF, Reply.json("{\"active\":true,\"expires_at\":\"2027-01-31\"}"));
        settings.set(Setting.TICKET_PROVIDER, TicketProvider.GITLAB.wireName());
        settings.set(Setting.TICKET_BASE_URL, tracker.baseUrl());
        settings.set(Setting.TICKET_PROJECT, "team/service");
        settings.set(Setting.TICKET_ALLOW_PRIVATE_URL, "true");
        settings.set(Setting.TICKET_CA, tracker.caPem);
        tickets.setToken("glpat-internal");

        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/suspended-tracker.git");
        repository.setBranch("main");
        repositoryId = repositories.save(repository).getId();
    }

    @AfterEach
    void putBack() {
        tracker.close();
        rows.putBack();
    }

    @Test
    @DisplayName("the sweep opens and closes nothing, the daily check asks nothing; re-enabled, all three reach it")
    void theTasksSendNothing() {
        long open = issue(IssueState.OPEN, null);
        long resolved = issue(IssueState.RESOLVED, "#9");
        disable();

        sweep.run();
        tokenCheck.run();

        assertThat(tracker.seen).as("no call reached the tracker").isEmpty();
        assertThat(issues.findById(open).orElseThrow().getTicketRef()).as("no ticket opened").isNull();
        assertThat(issues.findById(resolved).orElseThrow().getTicketRef()).as("the link kept, not closed")
                .isEqualTo("#9");
        assertThat(settings.get(Setting.TICKET_TOKEN)).as("the token kept in its row").isNotBlank();

        enable();
        sweep.run();
        tokenCheck.run();

        assertThat(issues.findById(open).orElseThrow().getTicketRef()).as("resumed: the ticket is opened").isEqualTo("#7");
        assertThat(issues.findById(resolved).orElseThrow().getTicketRef()).as("and the resolved one closed")
                .isEqualTo("CLOSED:#9");
        assertThat(tracker.count(ISSUES)).isOne();
        assertThat(tracker.count(ISSUES + "/9")).isOne();
        assertThat(tracker.count(SELF)).as("the daily check asks again").isOne();
    }

    @Test
    @DisplayName("saving a token stores it and probes nothing; the card reads suspended, naming tracker.gitlab")
    void theCardReadsSuspended() throws Exception {
        disable();
        String admin = asAdmin();

        mvc.perform(authenticated(put("/api/v1/settings/ticket-token"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("token", "glpat-replaced"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configured").value(true))
                .andExpect(jsonPath("$.state").value("suspended"))
                .andExpect(jsonPath("$.integration").value("tracker.gitlab"))
                .andExpect(jsonPath("$.checkedAt").doesNotExist())
                .andExpect(jsonPath("$.refusedStatus").doesNotExist());
        assertThat(tracker.seen).as("the save probed nothing").isEmpty();

        mvc.perform(authenticated(get("/api/v1/settings/ticket-token"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configured").value(true))
                .andExpect(jsonPath("$.state").value("suspended"))
                .andExpect(jsonPath("$.integration").value("tracker.gitlab"));

        enable();

        mvc.perform(authenticated(put("/api/v1/settings/ticket-token"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("token", "glpat-replaced"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("active"))
                .andExpect(jsonPath("$.expiresAt").value("2027-01-31T00:00:00Z"));
        assertThat(tracker.seen).singleElement().satisfies(request -> {
            assertThat(request.path()).isEqualTo(SELF);
            assertThat(request.headers()).as("the token stored while suspended is the one used")
                    .containsEntry("private-token", "glpat-replaced");
        });
    }

    @Test
    @DisplayName("attaching a ticket reference to an issue is refused 409 naming tracker.gitlab; re-enabled, it is attached")
    void attachingAReferenceIsRefused() throws Exception {
        long id = issue(IssueState.OPEN, null);
        disable();

        MvcResult refused = mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "#12"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(DISABLED))
                .andExpect(jsonPath("$.integration").value("tracker.gitlab"))
                .andReturn();
        assertThat(detailOf(refused)).isEqualTo("The integration \"tracker.gitlab\" is disabled on this installation; a "
                + "platform governor enables it with PUT /api/v1/integrations/tracker.gitlab/enabled.");
        assertThat(issues.findById(id).orElseThrow().getTicketRef()).isNull();

        enable();

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "#12"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticketRef").value("#12"));
        assertThat(tracker.seen).as("attaching calls no tracker either way").isEmpty();
    }

    @Test
    @DisplayName("linking a ticket of a disabled tracker is refused 409, one of an enabled tracker is linked")
    void linkingATicketIsRefused() throws Exception {
        long id = issue(IssueState.OPEN, null);
        disable();
        String admin = asAdmin();

        mvc.perform(authenticated(post("/api/v1/issues/" + id + "/tickets"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("provider", "gitlab", "ticketKey", "#12",
                                "ticketUrl", "https://gitlab.internal/team/service/-/issues/12"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(DISABLED))
                .andExpect(jsonPath("$.integration").value("tracker.gitlab"));
        assertThat(ticketLinks.findByIssueIdOrderByCreatedAtDescIdDesc(id)).isEmpty();

        mvc.perform(authenticated(post("/api/v1/issues/" + id + "/tickets"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("provider", "jira", "ticketKey", "SEC-12",
                                "ticketUrl", "https://jira.example.org/browse/SEC-12"))))
                .andExpect(status().isCreated());
        assertThat(ticketLinks.findByIssueIdOrderByCreatedAtDescIdDesc(id)).singleElement()
                .satisfies(link -> assertThat(link.getProvider()).isEqualTo("JIRA"));
    }

    private void disable() {
        integrations.switchTo(GITLAB, false, "test");
        tracker.seen.clear();
    }

    private void enable() {
        integrations.switchTo(GITLAB, true, "test");
    }

    /** A critical finding, which the built-in policy fails on: a candidate for a ticket, or one to close. */
    private long issue(IssueState state, String ticketRef) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setFingerprint("fp-suspended-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-" + System.nanoTime() % 100_000);
        issue.setSeverity(Severity.CRITICAL.wireName());
        issue.setState(state.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFixVersions("3.5.2");
        issue.setTicketRef(ticketRef);
        issue.setFirstSeenAt(Instant.parse("2026-09-01T10:00:00Z"));
        issue.setLastSeenAt(Instant.parse("2026-09-01T10:00:00Z"));
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
