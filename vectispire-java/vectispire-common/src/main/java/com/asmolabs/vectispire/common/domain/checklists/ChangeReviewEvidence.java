package com.asmolabs.vectispire.common.domain.checklists;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * What one reading of a forge said about how changes reach one branch of one repository — the evidence a
 * {@code change_review} line is judged on (decision 0037, lot G3). Read by the {@code forges} module through the
 * connection's token, stored as written, and read back here for the rule.
 *
 * <p><b>Two sources, each one absent rather than empty when it was not read.</b> The <em>settings</em> are a
 * configuration proof — approvals the forge requires before a merge, the author's own approval refused, a direct
 * push refused — which GitLab offers on its paid tiers and GitHub on every plan; GitLab's Community Edition has no
 * approval rule at all and answers 404. The <em>history</em> is what happened — the merge requests or pull requests
 * merged into the branch in the window, each with the number of distinct people other than its author who approved
 * it — and works on every edition. A source that could not be read says why ({@code settingsUnread}, {@code
 * historyUnread}): "not read" is never "nothing to read" (decision 0007).
 *
 * <p><b>No person's name is kept.</b> A change is its reference ({@code !12}, {@code #12}), its merge instant, and
 * counts: the author's identity decides whether an approval is a peer's when the forge is read, and is not needed
 * afterwards — an auditor follows the reference to the forge.
 *
 * @param forge {@code gitlab} or {@code github}: how a change is named, merge request or pull request
 * @param project the forge's full path of the repository, as the forge named it when read
 * @param branch the branch read — the rule's, or the default branch the forge named
 * @param windowDays how many days back from the reading the history reaches
 */
public record ChangeReviewEvidence(
        String forge,
        String project,
        String branch,
        int windowDays,
        Optional<Settings> settings,
        Optional<String> settingsUnread,
        Optional<History> history,
        Optional<String> historyUnread) {

    public ChangeReviewEvidence {
        Objects.requireNonNull(forge, "forge");
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(branch, "branch");
        Objects.requireNonNull(settings, "settings");
        Objects.requireNonNull(settingsUnread, "settingsUnread");
        Objects.requireNonNull(history, "history");
        Objects.requireNonNull(historyUnread, "historyUnread");
        if (settings.isPresent() == settingsUnread.isPresent() || history.isPresent() == historyUnread.isPresent()) {
            throw new IllegalArgumentException("Each source is either read or says why it was not.");
        }
    }

    /** What the forge calls one change: a merge request on GitLab, a pull request elsewhere. */
    public String changes() {
        return "gitlab".equals(forge) ? "merge requests" : "pull requests";
    }

    /**
     * The branch's configuration, as the forge stated it.
     *
     * @param requiredApprovals the approvals a merge into the branch requires — the largest any applicable rule
     *     asks; 0 where none does
     * @param authorApprovalPrevented whether the author's own approval is refused (always on GitHub)
     * @param directPushRefused whether a change can reach the branch only through a reviewed merge — a push
     *     straight to it is what a review rule does not see
     * @param described the configuration in one sentence, for the evidence
     */
    public record Settings(int requiredApprovals, boolean authorApprovalPrevented, boolean directPushRefused,
            String described) {

        public Settings {
            Objects.requireNonNull(described, "described");
        }

        /** Whether this configuration alone guarantees {@code minimumApprovals} peers on every change. */
        public boolean proves(int minimumApprovals) {
            return requiredApprovals >= minimumApprovals && authorApprovalPrevented && directPushRefused;
        }
    }

    /**
     * The changes merged into the branch within the window, newest first.
     *
     * @param complete false when the window held more changes than one reading takes: the counts are then not the
     *     window's, and the rule says so rather than judging a part
     */
    public record History(boolean complete, List<MergedChange> changes) {

        public History {
            changes = List.copyOf(changes);
        }
    }

    /**
     * @param reference {@code !12} on GitLab, {@code #12} on GitHub
     * @param peerApprovals distinct people other than the author whose approval stood when it was read
     * @param authorApproved whether the author approved their own change — counted nowhere, named in the evidence
     */
    public record MergedChange(String reference, Instant mergedAt, int peerApprovals, boolean authorApproved) {

        public MergedChange {
            Objects.requireNonNull(reference, "reference");
            Objects.requireNonNull(mergedAt, "mergedAt");
        }
    }

    // ------------------------------------------------------------------ the stored form

    /** As stored: what the measurement's digest covers, so it is written one way. */
    public String json() {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("forge", forge);
        node.put("project", project);
        node.put("branch", branch);
        node.put("windowDays", windowDays);
        settings.ifPresentOrElse(read -> {
            ObjectNode written = node.putObject("settings");
            written.put("requiredApprovals", read.requiredApprovals());
            written.put("authorApprovalPrevented", read.authorApprovalPrevented());
            written.put("directPushRefused", read.directPushRefused());
            written.put("described", read.described());
        }, () -> node.putNull("settings"));
        node.put("settingsUnread", settingsUnread.orElse(null));
        history.ifPresentOrElse(read -> {
            ObjectNode written = node.putObject("history");
            written.put("complete", read.complete());
            ArrayNode changes = written.putArray("changes");
            for (MergedChange change : read.changes()) {
                ObjectNode entry = changes.addObject();
                entry.put("reference", change.reference());
                entry.put("mergedAt", change.mergedAt().toString());
                entry.put("peerApprovals", change.peerApprovals());
                entry.put("authorApproved", change.authorApproved());
            }
        }, () -> node.putNull("history"));
        node.put("historyUnread", historyUnread.orElse(null));
        try {
            return JSON.writeValueAsString(node);
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("A change-review reading could not be written.", impossible);
        }
    }

    /** A stored reading read back, as {@link #json()} wrote it; a row that does not read is a defect. */
    public static ChangeReviewEvidence read(String stored) {
        JsonNode node;
        try {
            node = JSON.readTree(stored);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("A stored change-review reading does not read as JSON.", unreadable);
        }
        Optional<Settings> settings = Optional.ofNullable(node.get("settings")).filter(JsonNode::isObject)
                .map(read -> new Settings(read.path("requiredApprovals").asInt(),
                        read.path("authorApprovalPrevented").asBoolean(), read.path("directPushRefused").asBoolean(),
                        read.path("described").asText("")));
        Optional<History> history = Optional.ofNullable(node.get("history")).filter(JsonNode::isObject).map(read -> {
            List<MergedChange> changes = new ArrayList<>();
            for (JsonNode entry : read.path("changes")) {
                changes.add(new MergedChange(entry.path("reference").asText(), Instant.parse(entry.path("mergedAt").asText()),
                        entry.path("peerApprovals").asInt(), entry.path("authorApproved").asBoolean()));
            }
            return new History(read.path("complete").asBoolean(), changes);
        });
        return new ChangeReviewEvidence(node.path("forge").asText().toLowerCase(Locale.ROOT), node.path("project").asText(),
                node.path("branch").asText(), node.path("windowDays").asInt(), settings, text(node, "settingsUnread"),
                history, text(node, "historyUnread"));
    }

    private static Optional<String> text(JsonNode node, String name) {
        JsonNode value = node.get(name);
        return value == null || value.isNull() ? Optional.empty() : Optional.of(value.asText());
    }

    private static final ObjectMapper JSON = new ObjectMapper();
}
