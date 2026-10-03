package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Optional;

/**
 * One forge's answer to "how do changes reach this branch?" (decision 0037, lot G3): its settings, where it
 * offers them, and the history of what was merged — behind the interface the hourly reading is written against.
 *
 * <p><b>Every request goes through the pager it is handed</b> — opened on the connection's API origin with its
 * credential, the reading's deadline and the rate-limit bound — and never through a client of its own. The pager's
 * exceptions (a long rate limit, the deadline, a forge that does not answer, a page elsewhere) pass through
 * untouched: they are a reading that did not happen, and the previous one stands.
 *
 * <p><b>A refusal is an answer, written down</b>: a 403 or a 404 on the project, its merge requests or their
 * approvals says what the token may not see, which is what the line has to say ({@link Reading.Unreadable}, or a
 * source's own reason in the evidence). A 401 is the token's and makes the whole reading unreadable.
 */
public interface ReviewReader {

    ForgeKind kind();

    /** The headers that authenticate {@code token} to this forge's API, attached by the pager to its origin alone. */
    Map<String, String> credential(String token);

    /**
     * Reads one project's branch.
     *
     * @param forgeId the forge's stable id of the project, which a rename keeps
     * @param branch the rule's branch; empty for the default branch the forge names
     * @param since the window's start: the changes merged from then on are read
     * @param maxChanges past this many merged changes in the window the history is cut short, and says so
     */
    Reading read(OutboundPager pager, String api, String forgeId, Optional<String> branch, Instant since, int windowDays,
            int maxChanges);

    /** What a reading found. */
    sealed interface Reading permits Reading.Read, Reading.Unreadable {

        /** The forge answered about the project: the evidence, each source read or saying why not. */
        record Read(ChangeReviewEvidence evidence) implements Reading {}

        /** The forge would not answer about the project at all. */
        record Unreadable(String why) implements Reading {}
    }

    /** A path segment — a branch, a project's full name — as an API path takes it: slashes too. */
    static String segment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    static Optional<Instant> instant(JsonNode value) {
        if (value == null || !value.isTextual()) {
            return Optional.empty();
        }
        try {
            return Optional.of(OffsetDateTime.parse(value.asText()).toInstant());
        } catch (DateTimeParseException unreadable) {
            return Optional.empty();
        }
    }

    static String approvals(int count) {
        return count + (count == 1 ? " approval" : " approvals");
    }
}
