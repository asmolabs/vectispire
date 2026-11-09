package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.checklists.ChecklistReminder.Gap;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistReminder.Line;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistReminder.Message;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistReminder.ProfileLines;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistReminder.Unreached;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the weekly checklist reminder's words")
class ChecklistReminderTest {

    private static final LocalDate MONDAY = LocalDate.of(2026, 10, 19);

    @Test
    @DisplayName("a contact is told each line of theirs, by project and profile, with the page to fill them in")
    void toAContact() {
        Message message = ChecklistReminder.toContact(Optional.of("Ada"), List.of(
                        new ProfileLines(12, "Checkout", "PO", List.of(new Line(1, "Every account\nbelongs to one person."),
                                new Line(4, "Shared accounts are disabled."))),
                        new ProfileLines(30, "Ledger", "Arch", List.of(new Line(2, "Dependencies are pinned.")))),
                MONDAY, Optional.of("https://vectispire.example.org/"));

        assertThat(message.subject()).isEqualTo("[Vectispire] 3 checklist lines wait for you");
        assertThat(message.body())
                .startsWith("Hello Ada,\n\n3 checklist lines for which you are the contact are not filled in yet")
                .contains("Project \"Checkout\", profile PO — 2 lines\n  Line 1: Every account belongs to one person.\n"
                        + "  Line 4: Shared accounts are disabled.\n  https://vectispire.example.org/projects/12/checklist\n")
                .contains("Project \"Ledger\", profile Arch — 1 line\n  Line 2: Dependencies are pinned.\n"
                        + "  https://vectispire.example.org/projects/30/checklist\n")
                .contains("for the week of 2026-10-19");
    }

    @Test
    @DisplayName("an account with no printable name is greeted without one, and no address means no link")
    void noNameNoLink() {
        Message message = ChecklistReminder.toContact(Optional.empty(),
                List.of(new ProfileLines(12, "Checkout", "PO", List.of(new Line(1, "One control.")))), MONDAY,
                Optional.empty());

        assertThat(message.subject()).isEqualTo("[Vectispire] 1 checklist line waits for you");
        assertThat(message.body()).startsWith("Hello,\n\nOne checklist line for which you are the contact is not")
                .doesNotContain("http");
    }

    @Test
    @DisplayName("a long list is cut at twenty lines and counts the rest; a long control is cut and says so")
    void longListsAreCut() {
        List<Line> lines = IntStream.rangeClosed(1, 23).mapToObj(n -> new Line(n, "Control " + n + ".")).toList();
        String longControl = "x".repeat(400);
        Message message = ChecklistReminder.toContact(Optional.of("Ada"), List.of(
                new ProfileLines(12, "Checkout", "PO", lines),
                new ProfileLines(13, "Ledger", "BA", List.of(new Line(1, longControl)))), MONDAY, Optional.empty());

        assertThat(message.body()).contains("  Line 20: Control 20.\n  … and 3 lines more\n")
                .doesNotContain("Line 21:")
                .contains("  Line 1: " + "x".repeat(ChecklistReminder.CONTROL_SHOWN - 1) + "…\n");
    }

    @Test
    @DisplayName("a long control is cut between characters, never between the halves of a pair")
    void aCutKeepsPairsWhole() {
        String control = "x".repeat(ChecklistReminder.CONTROL_SHOWN - 2) + "\uD83D\uDE00" + "tail";
        Message message = ChecklistReminder.toContact(Optional.empty(), List.of(
                new ProfileLines(13, "Ledger", "BA", List.of(new Line(1, control)))), MONDAY, Optional.empty());

        assertThat(message.body()).contains("  Line 1: " + "x".repeat(ChecklistReminder.CONTROL_SHOWN - 2) + "…\n")
                .doesNotContain("\uD83D…");
    }

    @Test
    @DisplayName("a CISO is told each profile nobody is reminded for, and why")
    void toACiso() {
        Message message = ChecklistReminder.toCiso(List.of(
                        new Unreached(12, "Checkout", "BA", 3, Gap.NOBODY_LINKED),
                        new Unreached(12, "Checkout", "SII", 1, Gap.NO_EMAIL)),
                MONDAY, Optional.of("https://vectispire.example.org"));

        assertThat(message.subject()).isEqualTo("[Vectispire] 2 checklist profiles without a contact");
        assertThat(message.body())
                .contains("Project \"Checkout\", profile BA — 3 lines: no account is linked to it\n"
                        + "  https://vectispire.example.org/projects/12/checklist\n")
                .contains("profile SII — 1 line: the account linked to it has no e-mail address\n")
                .contains("under Contacts");
    }
}
