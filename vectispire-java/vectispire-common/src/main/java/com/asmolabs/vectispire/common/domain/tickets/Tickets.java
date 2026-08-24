package com.asmolabs.vectispire.common.domain.tickets;

import com.asmolabs.vectispire.common.domain.dependencies.Directness;
import com.asmolabs.vectispire.common.domain.exports.ExportableIssue.FixState;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * What a ticket says, and who it is for.
 *
 * <p>SARIF closes the loop towards the developer: a finding appears on the merge request that
 * introduced it. This closes it towards the organization — an issue nobody will fix this
 * afternoon has to exist where people plan their work, not only in a dashboard nothing obliges
 * them to open.
 *
 * <p><b>Driven by the gate policy, not by a second threshold.</b> "Open a ticket for what would
 * fail a build" is a rule an operator already knows how to reason about, and it leaves
 * <b>one place</b> where "serious enough to act on" is defined. A separate
 * {@code ticket_min_severity} would create two vocabularies that would diverge, and the first
 * bug report would be "why did it open a ticket for that without failing the build".
 *
 * <p>Pure: the formatting is tested with no ticket tracker.
 */
public final class Tickets {

    private Tickets() {}

    public static final String DEFAULT_JIRA_ISSUE_TYPE = "Bug";
    public static final List<String> DEFAULT_LABELS = List.of("vectispire", "security");

    /**
     * Cap per sweep.
     *
     * <p>A first pass over a mature backlog would otherwise open several hundred tickets at
     * once — a rate-limiting problem, and above all a social one.
     */
    public static final int MAX_TICKETS_PER_SWEEP = 20;

    /** How long a description may run inside a ticket body. */
    private static final int MAX_DESCRIPTION_LENGTH = 1000;

    /** What the formatting reads from an issue. Narrower than the entity, by design. */
    public record TicketableIssue(
            long id,
            FindingType type,
            String identifier,
            Severity severity,
            String packageName,
            String packageVersion,
            String fixVersions,
            FixState fixState,
            Directness directness,
            String filePath,
            Integer line,
            boolean kev,
            Double epssScore,
            String link,
            String description,
            String fingerprint) {}

    /** Short enough for a ticket list, precise enough to be searchable. */
    public static String title(TicketableIssue issue, String targetName) {
        String subject = blank(issue.identifier()) ? issue.type().wireName() : issue.identifier();
        String component = blank(issue.packageName()) ? "" : " — " + issue.packageName();
        String severity = severityOf(issue).wireName().toUpperCase(Locale.ROOT);

        return "[Vectispire][" + severity + "] " + subject + component + " (" + targetName + ")";
    }

    /**
     * The ticket body, written for whoever picks it up with no context.
     *
     * <p><b>The fixed version comes first among the details</b>, because it is what makes the
     * difference between a ticket closed today and a ticket dragged across three iterations.
     */
    public static String body(TicketableIssue issue, String targetName) {
        List<String> lines = new ArrayList<>(List.of(
                "Detected by Vectispire on **" + targetName + "**.",
                "",
                "- Type: " + issue.type().wireName(),
                "- Identifier: " + (blank(issue.identifier()) ? "—" : issue.identifier()),
                "- Severity: " + severityOf(issue).wireName()));

        if (!blank(issue.fixVersions())) {
            lines.add("- **Fixed in: " + issue.fixVersions() + "**");
        } else if (issue.fixState() == FixState.NOT_FIXED || issue.fixState() == FixState.WONT_FIX) {
            lines.add("- No published fix to date");
        }

        if (!blank(issue.packageName())) {
            lines.add("- Component: " + issue.packageName()
                    + (blank(issue.packageVersion()) ? "" : " " + issue.packageVersion()));
        }
        if (issue.directness() != Directness.UNKNOWN) {
            lines.add("- Dependency: "
                    + (issue.directness() == Directness.DIRECT ? "direct (declared by the project)" : "transitive"));
        }
        if (!blank(issue.filePath())) {
            lines.add("- Location: " + issue.filePath() + (issue.line() == null ? "" : ":" + issue.line()));
        }
        if (issue.kev()) {
            lines.add("- ⚠️ Known active exploitation (CISA KEV catalog)");
        }
        if (issue.epssScore() != null) {
            lines.add(String.format(Locale.ROOT, "- Exploitation probability (EPSS): %.1f%%", issue.epssScore() * 100));
        }
        if (!blank(issue.link())) {
            lines.add("- Reference: " + issue.link());
        }

        if (!blank(issue.description())) {
            // Truncated: a CVE description can run to several kilobytes, and a ticket you have
            // to scroll through to reach the conclusion does not get read.
            lines.add("");
            lines.add(issue.description().length() <= MAX_DESCRIPTION_LENGTH
                    ? issue.description()
                    : issue.description().substring(0, MAX_DESCRIPTION_LENGTH));
        }

        lines.add("");
        lines.add("Vectispire issue #" + issue.id() + " — fingerprint `" + issue.fingerprint() + "`.");
        lines.add("This ticket was opened because this issue would fail a build under the gate policy in force "
                + "for this target.");

        return String.join("\n", lines);
    }

    /** The labels, read from the setting. An empty list is a valid state. */
    public static List<String> parseLabels(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.split(",")).map(String::trim).filter(label -> !label.isEmpty()).toList();
    }

    private static Severity severityOf(TicketableIssue issue) {
        return issue.severity() == null ? Severity.UNKNOWN : issue.severity();
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
