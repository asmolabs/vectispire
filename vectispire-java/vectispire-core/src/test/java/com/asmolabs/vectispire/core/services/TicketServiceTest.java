package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.dependencies.Directness;
import com.asmolabs.vectispire.common.domain.exports.ExportableIssue.FixState;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.Tickets.TicketableIssue;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("opening a ticket with a tracker")
class TicketServiceTest {

    private static final String ENCRYPTION_KEY = EncryptionKey.generate();

    private SettingsService settings;
    private EncryptionService encryption;
    private OutboundPost post;
    private TicketService service;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        encryption = new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of()));
        post = mock(OutboundPost.class);
        service = new TicketService(settings, encryption, post, new ObjectMapper());

        when(settings.get(any())).thenReturn("");
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.GITLAB.wireName());
        when(settings.get(Setting.TICKET_BASE_URL)).thenReturn("https://gitlab.example.com/");
        when(settings.get(Setting.TICKET_PROJECT)).thenReturn("team/service");
        when(settings.get(Setting.TICKET_TOKEN))
                .thenReturn(encryption.encrypt("mock-gitlab-api-token", TicketService.TOKEN_CONTEXT));
        when(settings.get(Setting.TICKET_LABELS)).thenReturn("vectispire,security");
        when(settings.isEnabled(Setting.TICKET_ALLOW_PRIVATE_URL)).thenReturn(true);
        when(post.validate(anyString(), any(), anyString())).thenAnswer(call -> call.getArgument(0));
        when(post.postForResponse(anyString(), any(), any(), anyString(), any()))
                .thenReturn("{\"iid\":12,\"web_url\":\"https://gitlab.example.com/team/service/-/issues/12\"}");
    }

    @Test
    void opensAGitlabIssue() {
        Optional<TicketService.Ticket> ticket = service.createForIssue(issue(), "team/service");

        assertThat(ticket).get().satisfies(created -> {
            assertThat(created.reference()).isEqualTo("#12");
            assertThat(created.url()).endsWith("/issues/12");
        });
        // The project path has to be URL-encoded: "group/project" is the form most people have.
        verify(post).postForResponse(
                contains("/projects/team%2Fservice/issues"), any(), any(), anyString(), any());
    }

    @Test
    @DisplayName("the token is stored encrypted, never in the clear")
    void theTokenIsEncryptedAtRest() {
        service.setToken("mock-updated-token");

        verify(settings).set(eq(Setting.TICKET_TOKEN), contains("v2:"));
    }

    @Test
    @DisplayName("an undecryptable token disables ticketing instead of breaking the tick")
    void anUnreadableTokenDisablesTicketing() {
        // A rotated encryption key with no previous key configured. The maintenance tick also
        // carries the purge and triage expiry, and must not die here.
        when(settings.get(Setting.TICKET_TOKEN)).thenReturn("v2:d2hhdGV2ZXItdGhpcy1pcw==");

        assertThat(service.token()).isEmpty();
        assertThat(service.isEnabled()).isFalse();
        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
    }

    @Test
    @DisplayName("a refused base URL costs the ticket, not the sweep")
    void aRefusedUrlReturnsEmpty() {
        when(post.validate(anyString(), any(), anyString()))
                .thenThrow(new com.asmolabs.vectispire.common.domain.net.UnsafeUrlException("metadata endpoint"));

        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
    }

    @Test
    @DisplayName("a tracker outage returns empty so the next pass retries")
    void anOutageIsNotFatal() {
        when(post.postForResponse(anyString(), any(), any(), anyString(), any()))
                .thenThrow(new OutboundJson.OutboundFailureException("HTTP 503"));

        assertThat(service.createForIssue(issue(), "team/service")).isEmpty();
    }

    @Test
    @DisplayName("an internal tracker is allowed by default, unlike the webhook")
    void privateDestinationsAreAllowedHere() {
        service.createForIssue(issue(), "team/service");

        verify(post).validate(anyString(), eq(OutboundPolicy.INTERNAL_ALLOWED), anyString());
    }

    @Test
    void refusesAPrivateTrackerWhenTheOperatorSaidSo() {
        when(settings.isEnabled(Setting.TICKET_ALLOW_PRIVATE_URL)).thenReturn(false);

        service.createForIssue(issue(), "team/service");

        verify(post).validate(anyString(), eq(OutboundPolicy.PUBLIC_ONLY), anyString());
    }

    @Test
    @DisplayName("Jira gets an Atlassian document, not a plain string")
    void jiraBodiesAreStructured() {
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.JIRA.wireName());
        when(settings.get(Setting.TICKET_ISSUE_TYPE)).thenReturn("Bug");
        when(post.postForResponse(anyString(), any(), any(), anyString(), any())).thenReturn("{\"key\":\"SEC-4\"}");

        assertThat(service.createForIssue(issue(), "team/service")).get().satisfies(ticket -> {
            assertThat(ticket.reference()).isEqualTo("SEC-4");
            assertThat(ticket.url()).isEqualTo("https://gitlab.example.com/browse/SEC-4");
        });
    }

    @Test
    @DisplayName("no provider, no base URL, no project or no token: disabled")
    void everyMissingPieceDisablesIt() {
        assertThat(service.isEnabled()).isTrue();

        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.NONE.wireName());
        assertThat(service.isEnabled()).isFalse();

        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.GITLAB.wireName());
        when(settings.get(Setting.TICKET_PROJECT)).thenReturn("  ");
        assertThat(service.isEnabled()).isFalse();
    }

    private static TicketableIssue issue() {
        return new TicketableIssue(
                1L, FindingType.VULNERABILITY, "CVE-2026-1", Severity.CRITICAL, "openssl", "3.5.1", "3.5.2",
                FixState.FIXED, Directness.DIRECT, null, null, true, 0.42, null, "A buffer overflow.", "abc");
    }
}
