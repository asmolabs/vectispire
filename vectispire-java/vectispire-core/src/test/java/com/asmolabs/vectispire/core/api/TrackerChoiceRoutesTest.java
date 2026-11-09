package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Choosing a tracker whose integration is disabled, through {@code PUT /api/v1/settings} (decision 0040 §1, owner's
 * decision of 2026-10-13): refused 409 {@code integration-disabled} naming it, with nothing of the save written;
 * {@code none} always saved; and the tracker already configured, suspended by the switch, saved again unchanged so
 * that the rest of the section can still be saved.
 *
 * <p>{@code t_integration} is put back as it was found after each case ({@link IntegrationRows}).
 */
@DisplayName("choosing a tracker in the settings")
class TrackerChoiceRoutesTest extends ApiTestBase {

    private static final String DISABLED = "urn:vectispire:problem:integration-disabled";

    @Autowired
    private Integrations integrations;

    @Autowired
    private SettingsService settings;

    @Autowired
    private JdbcTemplate jdbc;

    private IntegrationRows rows;
    private String admin;

    @BeforeEach
    void remember() {
        rows = IntegrationRows.remember(jdbc);
        admin = asAdmin();
    }

    @AfterEach
    void putBack() {
        rows.putBack();
    }

    @Test
    @DisplayName("a disabled tracker is refused 409 naming it, and nothing of the save is written; enabled, it is chosen")
    void aDisabledTrackerIsRefused() throws Exception {
        switchTo(TicketProvider.JIRA, false);

        MvcResult refused = save(Map.of("ticket_provider", "jira", "ticket_labels", "security,refused"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(DISABLED))
                .andExpect(jsonPath("$.integration").value("tracker.jira"))
                .andReturn();
        assertThat(detailOf(refused)).isEqualTo("The integration \"tracker.jira\" is disabled on this installation; a "
                + "platform governor enables it with PUT /api/v1/integrations/tracker.jira/enabled.");
        assertThat(settings.get(Setting.TICKET_PROVIDER)).isEqualTo("none");
        assertThat(settings.get(Setting.TICKET_LABELS)).as("nothing of a refused save is written")
                .isNotEqualTo("security,refused");

        switchTo(TicketProvider.JIRA, true);

        save(Map.of("ticket_provider", "jira")).andExpect(status().isOk());
        assertThat(settings.get(Setting.TICKET_PROVIDER)).isEqualTo("jira");
    }

    @Test
    @DisplayName("moving from a suspended tracker to another disabled one is refused; to none, it is saved")
    void movingAwayFromASuspendedTracker() throws Exception {
        settings.set(Setting.TICKET_PROVIDER, "gitlab");
        switchTo(TicketProvider.GITLAB, false);
        switchTo(TicketProvider.GITHUB, false);

        save(Map.of("ticket_provider", "github"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(DISABLED))
                .andExpect(jsonPath("$.integration").value("tracker.github"));
        assertThat(settings.get(Setting.TICKET_PROVIDER)).isEqualTo("gitlab");

        save(Map.of("ticket_provider", "none")).andExpect(status().isOk());
        assertThat(settings.get(Setting.TICKET_PROVIDER)).isEqualTo("none");
    }

    @Test
    @DisplayName("the configured tracker, suspended, is saved again unchanged — in any case — with the rest of the section")
    void theSuspendedTrackerIsSavedAgain() throws Exception {
        settings.set(Setting.TICKET_PROVIDER, "gitlab");
        switchTo(TicketProvider.GITLAB, false);

        save(Map.of("ticket_provider", "GitLab", "ticket_project", "team/other")).andExpect(status().isOk());
        assertThat(settings.get(Setting.TICKET_PROJECT)).isEqualTo("team/other");
        assertThat(TicketProvider.fromWireName(settings.get(Setting.TICKET_PROVIDER))).contains(TicketProvider.GITLAB);
    }

    private ResultActions save(Map<String, String> body) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/settings"), admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(body)));
    }

    private void switchTo(TicketProvider tracker, boolean enabled) {
        integrations.switchTo(Integration.of(tracker), enabled, "test");
    }
}
