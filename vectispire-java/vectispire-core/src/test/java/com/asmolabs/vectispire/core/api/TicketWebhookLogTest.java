package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.tickets.TicketingWebhookService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * What an authenticated tracker can write into the control plane's log: its ticket key, on one line.
 */
@DisplayName("the ticket webhook's log line")
class TicketWebhookLogTest extends ApiTestBase {

    private static final String SECRET = "s3cr3t-partage-log";

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("a ticket key carrying a line break cannot forge a second log entry")
    void aTicketKeyStaysOnItsLine() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, SECRET);
        Logger logger = (Logger) LoggerFactory.getLogger(TicketingWebhookService.class);
        ListAppender<ILoggingEvent> captured = new ListAppender<>();
        captured.start();
        logger.addAppender(captured);
        try {
            int status = mvc.perform(post("/api/v1/tickets/webhook/jira")
                            .header("X-Vectispire-Token", SECRET)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"issue":{"key":"NOPE-1\\n2026-09-26T00:00:00Z INFO forged entry",
                                     "fields":{"status":{"name":"Closed"}}},
                                     "webhookEvent":"jira:issue_updated"}"""))
                    .andReturn().getResponse().getStatus();

            assertThat(status).isEqualTo(200);
            assertThat(captured.list)
                    .anySatisfy(event -> assertThat(event.getFormattedMessage()).contains("NOPE-1"))
                    .allSatisfy(event -> assertThat(event.getFormattedMessage()).doesNotContain("\n"));
        } finally {
            logger.detachAppender(captured);
        }
    }
}
