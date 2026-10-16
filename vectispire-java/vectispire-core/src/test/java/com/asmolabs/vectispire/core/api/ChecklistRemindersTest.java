package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.checklists.ChecklistReminderService;
import com.asmolabs.vectispire.core.notifications.MailNotificationChannel;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * The weekly checklist reminder over a real database (decision 0044): who is written to — each linked
 * contact its own lines, the CISOs the profiles nobody is reminded for — and the bookkeeping that keeps it
 * to once a week per recipient, which is the audit log and can only be checked against one. The relay is
 * the one thing replaced: what leaves is what this asserts.
 */
@DisplayName("the weekly checklist reminder")
class ChecklistRemindersTest extends ChecklistContactsTestBase {

    @MockitoBean
    private MailNotificationChannel mail;

    @Autowired
    private ChecklistReminderService reminders;

    private Account contact;
    private long cisoId;

    @BeforeEach
    void contacts() throws Exception {
        when(mail.hasRelay()).thenReturn(true);
        openChecklist(developer).andExpect(status().isCreated());

        contact = account(Role.USER);
        change(contact, row -> row.setEmail("contact@example.org"));
        link(champion.token(), "ARCH", contact.id()).andExpect(status().isOk());
        // PO is linked to an account with nowhere to write to; BA to nobody.
        link(champion.token(), "PO", developer.id()).andExpect(status().isOk());
        cisoId = accountWithoutSession(Role.CISO, "ciso@example.org");
        accountWithoutSession(Role.CISO, null);
        accountWithoutSession(Role.ADMIN, "admin@example.org");
        settings.set(Setting.CHECKLIST_REMINDERS_ENABLED, "true");
    }

    @Test
    @DisplayName("off by default, so an upgraded deployment writes to nobody")
    void offByDefault() {
        settings.set(Setting.CHECKLIST_REMINDERS_ENABLED, "false");
        assertThat(Setting.CHECKLIST_REMINDERS_ENABLED.defaultValue()).isEqualTo("false");

        assertThat(reminders.runOnce()).isZero();
        verify(mail, never()).sendTextTo(anyList(), anyString(), anyString());
    }

    @Test
    @DisplayName("on with no relay sends nothing and records nothing")
    void noRelay() {
        when(mail.hasRelay()).thenReturn(false);

        assertThat(reminders.runOnce()).isZero();
        verify(mail, never()).sendTextTo(anyList(), anyString(), anyString());
        assertThat(entries("CHECKLIST_REMINDER_SENT")).isEmpty();
    }

    @Test
    @DisplayName("a contact is told its own lines, a CISO the profiles that remind nobody, each once a week")
    void whoIsToldWhat() {
        assertThat(reminders.runOnce()).isEqualTo(2);

        ArgumentCaptor<String> body = ArgumentCaptor.forClass(String.class);
        verify(mail).sendTextTo(eq(List.of("contact@example.org")), eq("[Vectispire] 2 checklist lines wait for you"),
                body.capture());
        assertThat(body.getValue()).contains("Project \"Checkout\", profile Arch — 2 lines",
                        "Line 3: Every build publishes an SBOM.", "Line 5: Licences are reviewed before release.")
                .doesNotContain("Line 1:", "Line 4:");
        verify(mail).sendTextTo(eq(List.of("ciso@example.org")), eq("[Vectispire] 2 checklist profiles without a contact"),
                body.capture());
        assertThat(body.getValue())
                .contains("profile PO — 2 lines: the account linked to it has no e-mail address")
                .contains("profile BA — 1 line: no account is linked to it")
                .doesNotContain("Arch");
        verify(mail, times(2)).sendTextTo(anyList(), anyString(), anyString());
        assertThat(entries("CHECKLIST_REMINDER_SENT")).hasSize(2)
                .allSatisfy(entry -> assertThat(entry.getUserId()).isNull())
                .anySatisfy(entry -> assertThat(entry.getResourceId()).endsWith("/contact/" + contact.id()))
                .anySatisfy(entry -> assertThat(entry.getResourceId()).endsWith("/ciso/" + cisoId));

        reset(mail);
        when(mail.hasRelay()).thenReturn(true);
        assertThat(reminders.runOnce()).as("this week's are sent").isZero();
        verify(mail, never()).sendTextTo(anyList(), anyString(), anyString());
    }

    @Test
    @DisplayName("a filled-in line is not reminded of, and a profile with none left reminds nobody")
    void filledLinesAreNotReminded() throws Exception {
        List<Long> lines = lineIds(developer);
        answerYes(developer, lines.get(2));
        answerYes(developer, lines.get(4));

        reminders.runOnce();

        verify(mail, never()).sendTextTo(eq(List.of("contact@example.org")), anyString(), anyString());
        verify(mail).sendTextTo(eq(List.of("ciso@example.org")), anyString(), anyString());
    }

    @Test
    @DisplayName("a refused address is retried next turn, and alone: the others are not sent twice")
    void aFailureIsRetriedAlone() {
        doThrow(new IllegalStateException("relay refused")).when(mail)
                .sendTextTo(eq(List.of("contact@example.org")), anyString(), anyString());

        assertThat(reminders.runOnce()).isEqualTo(1);
        assertThat(entries("CHECKLIST_REMINDER_SENT")).singleElement()
                .satisfies(entry -> assertThat(entry.getResourceId()).endsWith("/ciso/" + cisoId));

        reset(mail);
        when(mail.hasRelay()).thenReturn(true);
        assertThat(reminders.runOnce()).isEqualTo(1);
        verify(mail).sendTextTo(eq(List.of("contact@example.org")), anyString(), anyString());
        verify(mail, never()).sendTextTo(eq(List.of("ciso@example.org")), anyString(), anyString());
    }

    @Test
    @DisplayName("a submitted checklist is nobody's to fill in, and reminds nobody")
    void aSubmittedChecklistIsNotReminded() throws Exception {
        jdbc.update("update t_checklist set status = 'submitted' where project_id = ?", project);

        assertThat(reminders.runOnce()).isZero();
        verify(mail, never()).sendTextTo(anyList(), anyString(), anyString());
    }

    @Autowired
    private org.springframework.jdbc.core.JdbcTemplate jdbc;
}
