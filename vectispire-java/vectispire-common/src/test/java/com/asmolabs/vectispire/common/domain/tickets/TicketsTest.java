package com.asmolabs.vectispire.common.domain.tickets;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.exports.ExportableIssue.FixState;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.tickets.Tickets.TicketableIssue;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("tickets")
class TicketsTest {

    private static TicketableIssue issue() {
        return new TicketableIssue(
                42, FindingType.VULNERABILITY, "CVE-2024-1234", Severity.HIGH, "requests", "2.31.0",
                "2.32.0", FixState.FIXED, com.asmolabs.vectispire.common.domain.dependencies.Directness.DIRECT, null, null, true, 0.9754, "https://example/CVE-2024-1234",
                null, "abc123");
    }

    @Test
    @DisplayName("the title is short enough for a list and precise enough to search")
    void titleIsSearchable() {
        assertThat(Tickets.title(issue(), "api-service"))
                .isEqualTo("[Vectispire][HIGH] CVE-2024-1234 — requests (api-service)");
    }

    @Test
    @DisplayName("falls back to the finding type when there is no identifier")
    void titleWithoutIdentifier() {
        TicketableIssue anonymous = new TicketableIssue(
                1, FindingType.SECRET, null, Severity.CRITICAL, null, null, null, null, com.asmolabs.vectispire.common.domain.dependencies.Directness.UNKNOWN, "app.py", 12,
                false, null, null, null, "f");

        assertThat(Tickets.title(anonymous, "api")).isEqualTo("[Vectispire][CRITICAL] secret (api)");
    }

    @Test
    @DisplayName("the fixed version leads the details")
    void fixedVersionComesFirst() {
        // It is what makes the difference between a ticket closed today and one dragged
        // across three iterations.
        String body = Tickets.body(issue(), "api-service");
        List<String> lines = body.lines().toList();

        assertThat(lines).contains("- **Fixed in: 2.32.0**");
        assertThat(lines.indexOf("- **Fixed in: 2.32.0**")).isLessThan(lines.indexOf("- Component: requests 2.31.0"));
    }

    @Test
    @DisplayName("says so plainly when there is no fix")
    void noPublishedFix() {
        TicketableIssue unfixable = new TicketableIssue(
                1, FindingType.VULNERABILITY, "CVE-1", Severity.HIGH, "pkg", "1.0", null, FixState.NOT_FIXED,
                com.asmolabs.vectispire.common.domain.dependencies.Directness.UNKNOWN, null, null, false, null, null, null, "f");

        assertThat(Tickets.body(unfixable, "api")).contains("- No published fix to date");
    }

    @Test
    @DisplayName("formats the EPSS score as a percentage with no stray space")
    void epssIsAPercentage() {
        // French typography puts a space before the percent sign; English does not, and the
        // body is English. It reached a real ticket once.
        assertThat(Tickets.body(issue(), "api")).contains("Exploitation probability (EPSS): 97.5%");
    }

    @Test
    @DisplayName("names active exploitation, and carries the fingerprint for correlation")
    void carriesTheSignals() {
        String body = Tickets.body(issue(), "api-service");

        assertThat(body)
                .contains("Known active exploitation (CISA KEV catalog)")
                .contains("Vectispire issue #42 — fingerprint `abc123`")
                .contains("would fail a build under the gate policy");
    }

    @Test
    @DisplayName("truncates a description that would bury the conclusion")
    void truncatesTheDescription() {
        TicketableIssue verbose = new TicketableIssue(
                1, FindingType.VULNERABILITY, "CVE-1", Severity.HIGH, null, null, null, null, com.asmolabs.vectispire.common.domain.dependencies.Directness.UNKNOWN, null, null,
                false, null, null, "x".repeat(5000), "f");

        assertThat(Tickets.body(verbose, "api")).contains("x".repeat(1000)).doesNotContain("x".repeat(1001));
    }

    @Test
    @DisplayName("omits what it does not know rather than printing a placeholder")
    void omitsUnknownFields() {
        TicketableIssue sparse = new TicketableIssue(
                1, FindingType.IAC, "CKV_AWS_1", Severity.MEDIUM, null, null, null, null, com.asmolabs.vectispire.common.domain.dependencies.Directness.UNKNOWN, null, null,
                false, null, null, null, "f");
        String body = Tickets.body(sparse, "api");

        assertThat(body).doesNotContain("- Component:").doesNotContain("- Dependency:").doesNotContain("- Location:");
    }

    @Test
    @DisplayName("an empty label list is a valid state")
    void labelsMayBeEmpty() {
        assertThat(Tickets.parseLabels(" vectispire , security ,")).containsExactly("vectispire", "security");
        assertThat(Tickets.parseLabels("")).isEmpty();
        assertThat(Tickets.parseLabels(null)).isEmpty();
    }

    @Test
    @DisplayName("the provider vocabulary parses, and knows when it is off")
    void providerVocabulary() {
        assertThat(TicketProvider.fromWireName("gitlab")).contains(TicketProvider.GITLAB);
        assertThat(TicketProvider.fromWireName("redmine")).isEmpty();
        assertThat(TicketProvider.NONE.isEnabled()).isFalse();
        assertThat(TicketProvider.JIRA.isEnabled()).isTrue();
    }
}
