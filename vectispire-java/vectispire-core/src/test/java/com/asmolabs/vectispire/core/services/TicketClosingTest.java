package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.core.services.outbound.OutboundJson;
import com.asmolabs.vectispire.core.services.outbound.OutboundPost;
import com.asmolabs.vectispire.core.services.outbound.PinnedHttpSender;
import com.asmolabs.vectispire.core.services.shared.SettingsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Closing a ticket, against a socket that answers the way each tracker does.
 *
 * <p><b>Why a server and not the mocked {@code OutboundPost} of {@code TicketServiceTest}.</b> The
 * defect was a verb and an identifier: every close went out as a POST, and ServiceNow's was
 * addressed by incident number where the Table API wants a {@code sys_id}. A mock of the sender
 * records whichever method this class chose to call, which is exactly the part that was wrong; the
 * real sender, guard and pin show what reached the wire.
 */
@DisplayName("closing a ticket reaches the record the tracker knows, with the verb it routes")
class TicketClosingTest {

    private static final String SYS_ID = "9d385017c611228701d22104cc95c371";

    /** Method and path-with-query of every request the fake tracker saw, in order. */
    private final List<String> seen = new CopyOnWriteArrayList<>();
    private static final List<String> POSTED = new CopyOnWriteArrayList<>();

    private HttpServer tracker;
    private SettingsService settings;
    private TicketService service;

    @BeforeEach
    void start() throws IOException {
        tracker = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        tracker.createContext("/", exchange -> {
            String request = exchange.getRequestMethod() + " " + exchange.getRequestURI().getRawPath()
                    + (exchange.getRequestURI().getRawQuery() == null ? "" : "?" + exchange.getRequestURI().getRawQuery());
            seen.add(request);
            if (exchange.getRequestMethod().equals("POST")) {
                POSTED.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            }
            answer(exchange, request);
        });
        tracker.start();

        String key = EncryptionKey.generate();
        EncryptionService encryption = new EncryptionService(new EncryptionProperties(Optional.of(key), List.of()));
        settings = mock(SettingsService.class);
        when(settings.get(any())).thenReturn("");
        when(settings.get(Setting.TICKET_BASE_URL))
                .thenReturn("http://127.0.0.1:" + tracker.getAddress().getPort());
        when(settings.get(Setting.TICKET_PROJECT)).thenReturn("team/service");
        when(settings.get(Setting.TICKET_TOKEN)).thenReturn(encryption.encrypt("token", TicketService.TOKEN_CONTEXT));
        when(settings.isEnabled(Setting.TICKET_ALLOW_PRIVATE_URL)).thenReturn(true);

        ObjectMapper json = new ObjectMapper();
        OutboundUrlGuard guard = new OutboundUrlGuard();
        PinnedHttpSender sender = new PinnedHttpSender();
        service = new TicketService(
                settings, encryption, new OutboundPost(sender, guard, json), new OutboundJson(sender, guard, json), json);
    }

    @AfterEach
    void stop() {
        tracker.stop(0);
    }

    /** Answers only what the real API routes; anything else is the 405/404 the tracker would give. */
    private static void answer(HttpExchange exchange, String request) throws IOException {
        String body;
        int status;
        if (request.equals("GET /api/now/table/incident?sysparm_query=number%3DINC0012345&sysparm_fields=sys_id&sysparm_limit=1")) {
            status = 200;
            body = "{\"result\":[{\"sys_id\":\"" + SYS_ID + "\"}]}";
        } else if (request.startsWith("GET /api/now/table/incident?")) {
            // What the Table API answers a query matching nothing: 200 and an empty list.
            status = 200;
            body = "{\"result\":[]}";
        } else if (request.equals("GET /rest/api/3/issue/SEC-42/transitions")) {
            // A workflow whose "Done" is not 31: the id belongs to the project, not to Jira.
            status = 200;
            body = "{\"transitions\":[{\"id\":\"21\",\"to\":{\"statusCategory\":{\"key\":\"indeterminate\"}}},"
                    + "{\"id\":\"41\",\"to\":{\"statusCategory\":{\"key\":\"done\"}}}]}";
        } else if (request.equals("GET /rest/api/3/issue/SEC-7/transitions")) {
            status = 200;
            body = "{\"transitions\":[{\"id\":\"21\",\"to\":{\"statusCategory\":{\"key\":\"indeterminate\"}}}]}";
        } else if (request.equals("POST /rest/api/3/issue/SEC-42/transitions")) {
            status = 204;
            body = "";
        } else if (request.equals("PATCH /api/now/table/incident/" + SYS_ID)
                || request.equals("PUT /api/v4/projects/team%2Fservice/issues/105")
                || request.equals("PATCH /repos/team/service/issues/42")) {
            status = 200;
            body = "{}";
        } else {
            status = 405;
            body = "{\"error\":\"not routed\"}";
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Test
    @DisplayName("a ServiceNow incident number is resolved to its sys_id, then PATCHed")
    void aServiceNowNumberIsResolvedFirst() {
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.SERVICENOW.wireName());

        assertThat(service.closeTicket("INC0012345", "clean scan")).isTrue();
        assertThat(seen).last().isEqualTo("PATCH /api/now/table/incident/" + SYS_ID);
    }

    @Test
    @DisplayName("a stored sys_id is used as it is, with no lookup")
    void aServiceNowSysIdNeedsNoLookup() {
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.SERVICENOW.wireName());

        assertThat(service.closeTicket(SYS_ID, "clean scan")).isTrue();
        assertThat(seen).containsExactly("PATCH /api/now/table/incident/" + SYS_ID);
    }

    @Test
    @DisplayName("an incident ServiceNow does not know is a failed close, not a request to a guessed path")
    void anUnknownNumberIsNotClosed() {
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.SERVICENOW.wireName());

        assertThat(service.closeTicket("INC0099999", "clean scan")).isFalse();
        assertThat(seen).noneMatch(request -> request.startsWith("PATCH"));
    }

    @Test
    @DisplayName("a GitLab issue is closed with PUT, the only verb its issue route accepts")
    void gitlabClosesWithPut() {
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.GITLAB.wireName());

        assertThat(service.closeTicket("#105", "clean scan")).isTrue();
        assertThat(seen).containsExactly("PUT /api/v4/projects/team%2Fservice/issues/105");
    }

    @Test
    @DisplayName("a GitHub issue is closed with PATCH, the verb GitHub documents for an update")
    void githubClosesWithPatch() {
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.GITHUB.wireName());

        assertThat(service.closeTicket("#42", "clean scan")).isTrue();
        assertThat(seen).containsExactly("PATCH /repos/team/service/issues/42");
    }

    @Test
    @DisplayName("a Jira issue takes the transition its workflow offers towards a done status")
    void jiraTakesTheDoneTransitionItIsOffered() {
        // It posted transition 31 whatever the workflow: elsewhere another transition, or none.
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.JIRA.wireName());
        when(settings.get(Setting.TICKET_PROJECT)).thenReturn("SEC");
        POSTED.clear();

        assertThat(service.closeTicket("SEC-42", "clean scan")).isTrue();
        assertThat(seen).containsExactly(
                "GET /rest/api/3/issue/SEC-42/transitions", "POST /rest/api/3/issue/SEC-42/transitions");
        assertThat(POSTED).singleElement().asString().contains("\"41\"").doesNotContain("\"31\"");
    }

    @Test
    @DisplayName("a Jira workflow offering no done transition leaves the issue open, and says so")
    void jiraWithoutADoneTransitionIsNotClosed() {
        when(settings.get(Setting.TICKET_PROVIDER)).thenReturn(TicketProvider.JIRA.wireName());
        when(settings.get(Setting.TICKET_PROJECT)).thenReturn("SEC");

        assertThat(service.closeTicket("SEC-7", "clean scan")).isFalse();
        assertThat(seen).noneMatch(request -> request.startsWith("POST"));
    }
}
