package com.asmolabs.vectispire.core.tickets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.dependencies.Directness;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.exports.ExportableIssue.FixState;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.Tickets.TicketableIssue;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.gate.ActiveGatePolicies;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicyRepository;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPost;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A tracker behind an internal CA, over real TLS: {@link ForgeStub} serves HTTPS on loopback with a certificate
 * from a throwaway CA no trust store holds — the shape of a self-managed GitLab, Jira or ServiceNow.
 *
 * <p><b>Why the real sender.</b> The defect was a parameter nobody passed: every tracker call went out with the
 * runtime's trust store alone, and a mock of {@code OutboundPost} records whichever method this class calls —
 * not whether the handshake would have succeeded. Here the sender, the guard and the pin are real; only the
 * settings are a mock.
 */
@DisplayName("a tracker behind an internal CA")
class TicketTrackerCaTest {

    private static final String PROJECT = "/api/v4/projects/team%2Fservice/issues";

    private ForgeStub tracker;
    private SettingsService settings;
    private TicketService service;

    @BeforeEach
    void start() throws Exception {
        tracker = ForgeStub.start()
                .route(PROJECT, Reply.json("{\"iid\":7,\"web_url\":\"https://gitlab.internal/team/service/-/issues/7\"}"))
                .route(PROJECT + "/7", Reply.json("{}"));

        EncryptionService encryption =
                new EncryptionService(new EncryptionProperties(Optional.of(EncryptionKey.generate()), List.of()));
        settings = mock(SettingsService.class);
        when(settings.get(any())).thenReturn("");
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.GITLAB.wireName());
        when(settings.get(Setting.TICKET_BASE_URL)).thenReturn(tracker.baseUrl());
        when(settings.get(Setting.TICKET_PROJECT)).thenReturn("team/service");
        when(settings.get(Setting.TICKET_TOKEN)).thenReturn(encryption.encrypt("glpat-internal", TicketService.TOKEN_CONTEXT));
        when(settings.isEnabled(Setting.TICKET_ALLOW_PRIVATE_URL)).thenReturn(true);

        ObjectMapper json = new ObjectMapper();
        OutboundUrlGuard guard = new OutboundUrlGuard();
        PinnedHttpSender sender = new PinnedHttpSender();
        service = new TicketService(settings, encryption, new OutboundPost(sender, guard, json),
                new OutboundJson(sender, guard, json), json, Clock.systemUTC(), new TrackerTokenState(settings, event -> {}, org.springframework.transaction.support.TransactionOperations.withoutTransaction()));
    }

    @AfterEach
    void stop() {
        tracker.close();
    }

    @Test
    @DisplayName("without the CA pinned the handshake fails: no ticket, and nothing reached the tracker")
    void withoutTheCaNothingIsOpened() {
        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
        assertThat(service.closeTicket("#7", "clean scan")).isFalse();

        // Refused in the handshake, before a single HTTP request: the token never left.
        assertThat(tracker.seen).isEmpty();
    }

    @Test
    @DisplayName("with the tracker's CA pinned, a GitLab issue is opened and closed, the token presented to it")
    void withTheCaAGitlabIssueIsOpenedAndClosed() {
        pin(tracker.caPem);

        assertThat(service.createForIssue(issue(), "team/service")).get()
                .satisfies(ticket -> assertThat(ticket.reference()).isEqualTo("#7"));
        assertThat(service.closeTicket("#7", "clean scan")).isTrue();

        assertThat(tracker.seen).extracting(ForgeStub.Seen::method, ForgeStub.Seen::path)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple("POST", PROJECT),
                        org.assertj.core.groups.Tuple.tuple("PUT", PROJECT + "/7"));
        assertThat(tracker.seen.getFirst().headers()).containsEntry("private-token", "glpat-internal");
    }

    @Test
    @DisplayName("Jira's transitions lookup and the transition itself go through the pinned CA")
    void jiraClosesThroughThePinnedCa() {
        pin(tracker.caPem);
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.JIRA.wireName());
        when(settings.get(Setting.TICKET_PROJECT)).thenReturn("SEC");
        tracker.route("/rest/api/3/issue/SEC-42/transitions", Reply.json(
                "{\"transitions\":[{\"id\":\"41\",\"to\":{\"statusCategory\":{\"key\":\"done\"}}}]}"));
        tracker.route("/rest/api/3/issue", Reply.json("{\"key\":\"SEC-43\"}"));

        assertThat(service.createForIssue(issue(), "team/service")).get()
                .satisfies(ticket -> assertThat(ticket.reference()).isEqualTo("SEC-43"));
        assertThat(service.closeTicket("SEC-42", "clean scan")).isTrue();

        assertThat(tracker.seen).extracting(ForgeStub.Seen::method)
                .containsExactly("POST", "GET", "POST");
    }

    @Test
    @DisplayName("GitHub and ServiceNow, opened and closed through the pinned CA")
    void githubAndServiceNowToo() {
        pin(tracker.caPem);
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.GITHUB.wireName());
        tracker.route("/repos/team/service/issues", Reply.json("{\"number\":3,\"html_url\":\"x\"}"));
        tracker.route("/repos/team/service/issues/3", Reply.json("{}"));
        assertThat(service.createForIssue(issue(), "team/service")).isPresent();
        assertThat(service.closeTicket("#3", "clean scan")).isTrue();

        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.SERVICENOW.wireName());
        String sysId = "9d385017c611228701d22104cc95c371";
        tracker.route("/api/now/table/incident", Reply.json("{\"result\":{\"number\":\"INC0012345\",\"sys_id\":\"" + sysId + "\"}}"));
        tracker.route("/api/now/table/incident?sysparm_query=number%3DINC0012345&sysparm_fields=sys_id&sysparm_limit=1",
                Reply.json("{\"result\":[{\"sys_id\":\"" + sysId + "\"}]}"));
        tracker.route("/api/now/table/incident/" + sysId, Reply.json("{}"));
        assertThat(service.createForIssue(issue(), "team/service")).isPresent();
        assertThat(service.closeTicket("INC0012345", "clean scan")).isTrue();

        assertThat(tracker.seen).extracting(ForgeStub.Seen::method)
                .containsExactly("POST", "PATCH", "POST", "GET", "PATCH");
    }

    @Test
    @DisplayName("a CA that is not the tracker's issuer is no way in: the pinned CA replaces the store, it is not a key")
    void anotherCaDoesNotPass() throws Exception {
        try (ForgeStub other = ForgeStub.start()) {
            pin(other.caPem);

            assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
            assertThat(tracker.seen).isEmpty();
        }
    }

    @Test
    @DisplayName("a pinned CA that has lapsed since it was saved stops the calls, and never falls back on the store")
    void aLapsedCaStopsTheCalls() {
        pin(tracker.caPem);
        // A year and a month on, the throwaway CA has expired; the handshake itself would still pass, the JDK
        // reading no trust anchor's dates — which is why the CA is checked before every call.
        ObjectMapper json = new ObjectMapper();
        OutboundUrlGuard guard = new OutboundUrlGuard();
        PinnedHttpSender sender = new PinnedHttpSender();
        when(settings.get(Setting.TICKET_TOKEN)).thenReturn("glpat-legacy-clear");
        service = new TicketService(settings,
                new EncryptionService(new EncryptionProperties(Optional.of(EncryptionKey.generate()), List.of())),
                new OutboundPost(sender, guard, json), new OutboundJson(sender, guard, json), json,
                Clock.fixed(Instant.now().plus(Duration.ofDays(400)), ZoneOffset.UTC), new TrackerTokenState(settings, event -> {}, org.springframework.transaction.support.TransactionOperations.withoutTransaction()));

        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
        assertThat(service.closeTicket("#7", "clean scan")).isFalse();
        assertThat(tracker.seen).isEmpty();
        // Still shown, so that somebody replaces it.
        assertThat(service.pinnedCa()).get().satisfies(ca -> assertThat(ca.subject()).isEqualTo("CN=Forge Test CA"));
    }

    @Test
    @DisplayName("what an administrator pastes is read as a forge's CA is: a leaf, a key or noise is refused in words")
    void anInvalidPemIsRefused() {
        assertThat(service.caToPin("  ")).isEmpty();
        assertThat(service.caToPin(tracker.caPem)).isPresent();
        assertThatThrownBy(() -> service.caToPin("not a certificate"))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageStartingWith("The tracker CA");
        // A marker the reader cannot read ends the bundle silently: refused rather than pinned in part.
        assertThatThrownBy(() -> service.caToPin(tracker.caPem
                        + tracker.caPem.replaceFirst("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE")))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("-----BEGIN line that cannot be read");
    }

    @Test
    @DisplayName("the sweep leaves the issue without a ticket while the handshake fails, and opens it once the CA is pinned")
    void theSweepRetriesOnceTheCaIsPinned() {
        IssueRepository issues = mock(IssueRepository.class);
        GatePolicyRepository policies = mock(GatePolicyRepository.class);
        TargetNaming naming = mock(TargetNaming.class);
        when(naming.all()).thenReturn(new TargetNaming.Names(Map.of(), Map.of()));
        when(policies.findByIsActiveTrue()).thenReturn(List.of());
        when(issues.findActionableWithoutTicket(anyString(), any(), any())).thenReturn(List.of(critical()));
        TicketSweepService sweep = new TicketSweepService(new IssueCatalog(issues), new ActiveGatePolicies(policies),
                naming, service, mock(AuditLogService.class));

        assertThat(sweep.sweep(20)).isZero();
        verify(issues, never()).attachTicket(anyLong(), anyString(), anyString());

        pin(tracker.caPem);
        assertThat(sweep.sweep(20)).isEqualTo(1);
        verify(issues).attachTicket(1L, "#7", "https://gitlab.internal/team/service/-/issues/7");
    }

    private void pin(String pem) {
        when(settings.get(Setting.TICKET_CA)).thenReturn(pem);
    }

    private static TicketableIssue issue() {
        return new TicketableIssue(
                1L, FindingType.VULNERABILITY, "CVE-2026-1", Severity.CRITICAL, "openssl", "3.5.1", "3.5.2",
                FixState.FIXED, Directness.DIRECT, null, null, true, 0.42, null, "A buffer overflow.", "abc");
    }

    private static IssueEntity critical() {
        IssueEntity issue = new IssueEntity();
        issue.setId(1L);
        issue.setRepoId(5L);
        issue.setState(IssueState.OPEN.wireName());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-1");
        issue.setSeverity(Severity.CRITICAL.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFixVersions("3.5.2");
        return issue;
    }
}
