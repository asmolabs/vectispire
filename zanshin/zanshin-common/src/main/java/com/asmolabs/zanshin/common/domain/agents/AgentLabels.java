package com.asmolabs.zanshin.common.domain.agents;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Which agent is allowed to run which scan.
 *
 * <p><b>The queue was routed by no criterion at all.</b> Any registered agent claimed any
 * scan, and whoever asked first was served. An agent placed in a less-trusted segment —
 * because it has to reach a repository there, which is precisely why remote agents exist —
 * could therefore claim every other repository's scans, and receive their deployment keys with
 * them.
 *
 * <p>Neither end-to-end sealing nor local mode closes this: the first protects the key <em>in
 * transit</em> and does open it at the claimant, the second removes the key but still lets the
 * agent read the source. The only answer is to say <b>where</b> a scan is allowed to go.
 *
 * <p><b>A label, not a list of agents.</b> Naming agents makes every machine replacement a
 * change to every repository it serves; a label describes a <em>capability</em> — "reaches the
 * production network", "cleared for customer repositories" — and a new agent carries it from
 * the moment it registers.
 *
 * <p><b>Closed by default on the agent's side, open on the scan's side.</b> A scan with no
 * requirement goes to anyone: that is the previous behaviour, and imposing otherwise
 * retroactively would stop every existing queue on the first deployment. An agent with no
 * label, on the other hand, only takes work with no requirement — it does not "match
 * everything". The reverse reading is the seductive one, and it makes the requirement
 * inoperative at the first agent registered without thinking about it.
 */
public final class AgentLabels {

    private AgentLabels() {}

    private static final String SEPARATOR = ",";

    /**
     * An agent's labels, normalized.
     *
     * <p>Whitespace stripped and case lowered: "Production" and "production", typed six months
     * apart on two different screens, must mean the same thing — otherwise a scan waits
     * indefinitely for an agent that is right there, and nothing on screen explains why.
     */
    public static List<String> parse(String raw) {
        if (raw == null) {
            return List.of();
        }
        // Commas alone are not labels: without the filter, an empty string enters the list and
        // satisfies an empty requirement.
        return Arrays.stream(raw.split(SEPARATOR))
                .map(AgentLabels::normalize)
                .filter(label -> !label.isEmpty())
                .toList();
    }

    /**
     * A target's requirement — <b>one</b> label, normalized, or empty for "none".
     *
     * <p><b>This is the case that would silently jam a queue.</b> A form field that has been
     * cleared means "no requirement any more"; storing what is left as it is gives a
     * requirement no agent ever satisfies, and the scan waits forever with nothing saying why.
     *
     * <p>So anything that does not reduce to exactly one label becomes none. That covers the
     * blank string, and it covers a value containing a comma — which is worth spelling out,
     * because such a requirement is <b>unsatisfiable by construction</b>: {@link #parse} splits
     * an agent's labels on the comma, so no agent can ever carry a label containing one.
     * Storing it would be storing a permanent block.
     *
     * <p>Between the two failure modes, none is the safe one: the scan runs on any agent, which
     * is the documented default. Unsatisfiable means the scan never runs at all.
     */
    public static Optional<String> normalizeRequirement(String raw) {
        List<String> labels = parse(raw);
        return labels.size() == 1 ? Optional.of(labels.getFirst()) : Optional.empty();
    }

    /**
     * Can this agent run a scan carrying this requirement?
     *
     * <p>Kept apart from the SQL query so the same decision is checkable on both sides: the
     * queue filters in the database, and the dispatcher confirms it on the row it actually
     * took. A rule written once, in SQL, would be re-argued at every review.
     */
    public static boolean accepts(List<String> agentLabels, Optional<String> required) {
        return required.map(agentLabels::contains).orElse(true);
    }

    private static String normalize(String raw) {
        return raw.trim().toLowerCase(Locale.ROOT);
    }
}
