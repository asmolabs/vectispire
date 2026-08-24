package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import java.time.Instant;

/**
 * An issue, plus the target it was found on.
 *
 * <p><b>The backlog is global, and an issue only carried its target's numeric id.</b> Reading a
 * hundred rows told nobody which repository or image each one came from — and ordering the list
 * by severity made that worse rather than better, because consecutive rows now jump from one
 * target to another with nothing on screen saying so.
 *
 * <p><b>Resolved here rather than in the browser.</b> The client would have to load the full
 * repository and container lists and re-derive the name, which means a second naming rule; and
 * two naming rules for one target is how the same thing comes to be called two things. The
 * server already owns that rule.
 *
 * <p>{@code @JsonUnwrapped} keeps the wire shape flat: the entity's fields stay where every
 * existing client already reads them, and the two new ones sit alongside. The alternative —
 * a record restating all thirty fields — would be a second definition of an issue, drifting
 * from the first the day a column is added.
 *
 * @param targetName never null in practice, but not guaranteed: an issue whose target was
 *     deleted in the same request keeps its id and loses its name, and a blank cell is a better
 *     answer there than a crash
 * @param slaDueAt when this issue's remediation window closes, or {@code null} when none applies
 *     — a severity with no window, an issue already settled or closed. <b>Computed on the server
 *     like the gate verdict</b>: a client re-deriving it from the policy would be a second
 *     implementation of the deadline, and the two would disagree the day the policy changes
 * @param slaState {@code on_time}, {@code due_soon} or {@code overdue}; {@code null} with no
 *     deadline. Sent as a state rather than left to the client to infer from the date, so that
 *     "late" means the same thing on the screen, in an export and in a report
 * @param slaDays days until due, negative when late, {@code null} with no deadline
 */
public record BacklogEntry(
        @JsonUnwrapped IssueEntity issue,
        String targetKind,
        String targetName,
        Instant slaDueAt,
        String slaState,
        Long slaDays) {}
