package com.asmolabs.vectispire.core.services.issues;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.paging.RegisterCursor;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import com.asmolabs.vectispire.core.services.targets.TargetNaming;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * What somebody decided not to fix, and under what terms.
 *
 * <p><b>Assembled here rather than in the controller because it has two readers.</b> The route
 * serves the screen; the evidence bundle seals the same rows into an archive an assessor opens
 * months later. Two callers building the register separately is how the two drift, and a register
 * that disagrees with the export of itself is worse than either alone.
 *
 * <p>The narrative — why the register exists, what it deliberately omits — is on the controller,
 * where somebody reading the API finds it.
 */
@Service
public class ExceptionsRegisterService {

    /** Past this, a register is exported rather than read. */
    public static final int MAX_ENTRIES = 500;

    /** The origin {@code IssueTriageService} writes for a periodic review. */
    private static final String REVIEW = "review";

    /** The decisions that are exceptions: granted, and awaiting a second pair of eyes. */
    private static final List<String> DECISIONS =
            List.of(TriageStatus.NOT_AFFECTED.wireName(), TriageStatus.PENDING_APPROVAL.wireName());

    private final TriageEvents events;
    private final Issues issues;
    private final TargetNaming naming;
    private final Clock clock;

    public ExceptionsRegisterService(TriageEvents events, Issues issues, TargetNaming naming, Clock clock) {
        this.events = events;
        this.issues = issues;
        this.naming = naming;
        this.clock = clock;
    }

    /**
     * @param lapsed the expiry has passed and nothing has been decided since
     * @param origin who made the decision — a person, or a rule that applied it
     * @param lastReviewedAt when somebody last revisited this exception and left it standing, or
     *     null when nobody has since it was granted. <b>Null is the interesting value</b>
     * @param lastReviewedBy who did
     */
    public record ExceptionEntry(
            @JsonProperty("issue_id") Long issueId,
            String identifier,
            String severity,
            @JsonProperty("target_kind") String targetKind,
            @JsonProperty("target_id") Long targetId,
            @JsonProperty("target_name") String targetName,
            String decision,
            String justification,
            String comment,
            String actor,
            String origin,
            @JsonProperty("decided_at") Instant decidedAt,
            @JsonProperty("expires_at") Instant expiresAt,
            boolean lapsed,
            @JsonProperty("last_reviewed_at") Instant lastReviewedAt,
            @JsonProperty("last_reviewed_by") String lastReviewedBy) {}

    /**
     * @param granted exemptions in force
     * @param awaitingApproval requested, not yet granted — the four-eyes queue
     * @param lapsed granted, expired, and not revisited. <b>The figure worth acting on</b>
     * @param neverReviewed granted and never revisited since. The figure an assessment asks for
     * @param nextCursor where the next page starts, or null at the end of the register. Taken
     *     from the rows <b>read</b>, never from the rows returned — see {@link #register}
     */
    public record Register(
            List<ExceptionEntry> entries,
            long granted,
            @JsonProperty("awaiting_approval") long awaitingApproval,
            long lapsed,
            @JsonProperty("never_reviewed") long neverReviewed,
            @JsonProperty("next_cursor") String nextCursor) {}

    /**
     * The register, newest first, narrowed to what the caller may see.
     *
     * <p><b>The limit bounds what is read, not what is returned.</b> Visibility is applied after
     * the read, by {@code permits} — a reader restricted to two repositories sees only their rows
     * among the ones this page covers, rather than a page assembled in SQL from somebody else's.
     *
     * <p><b>And so the cursor is taken from the rows read.</b> A restricted reader's page can come
     * back empty while the register still holds exceptions they may see — everything in that
     * window belonged to somebody else. A cursor drawn from the visible rows would be absent
     * there, the client would stop, and the register would have ended one page in for the reader
     * least able to tell.
     *
     * @param limit how many decisions to read; clamped to {@link #MAX_ENTRIES}
     * @param cursor where to continue, or null to start at the newest
     * @param allowed the caller's allowance
     */
    @Transactional(readOnly = true)
    public Register register(int limit, String cursor, Visibility allowed) {
        int capped = Math.clamp(limit, 1, MAX_ENTRIES);
        List<IssueEntity> excepted = RegisterCursor.parse(cursor)
                .flatMap(from -> asId(from.id())
                        .map(id -> issues.findWithExceptionAfter(DECISIONS, from.at(), id, Limit.of(capped))))
                .orElseGet(() -> issues.findWithException(DECISIONS, Limit.of(capped)));

        Map<Long, List<TriageEventEntity>> history = events
                .findForIssues(excepted.stream().map(IssueEntity::getId).toList())
                .stream()
                .collect(Collectors.groupingBy(TriageEventEntity::getIssueId));

        List<Long> repoIds = excepted.stream()
                .map(IssueEntity::getRepoId)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        List<Long> containerIds = excepted.stream()
                .map(IssueEntity::getContainerId)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        TargetNaming.Names names = naming.forIds(repoIds, containerIds);

        Instant now = clock.instant();
        List<ExceptionEntry> entries = excepted.stream()
                .map(issue -> entry(
                        issue, history.getOrDefault(issue.getId(), List.of()), names, allowed, now))
                .filter(Objects::nonNull)
                .toList();

        return new Register(
                entries,
                entries.stream()
                        .filter(entry -> TriageStatus.NOT_AFFECTED.wireName().equals(entry.decision()))
                        .count(),
                entries.stream()
                        .filter(entry -> TriageStatus.PENDING_APPROVAL.wireName().equals(entry.decision()))
                        .count(),
                entries.stream().filter(ExceptionEntry::lapsed).count(),
                entries.stream().filter(entry -> entry.lastReviewedAt() == null).count(),
                nextCursor(excepted, capped));
    }

    /**
     * Where the next page starts, or nothing when this one reached the end.
     *
     * <p>A short read exhausts the register; a full one may not, and the cursor names the last row
     * <em>read</em> whether or not the caller was allowed to see it.
     *
     * <p>A row with no triage instant cannot be pointed at, and does not need to be: it sorts last
     * under {@code desc}, so it only ever appears on a final page — and a final page is short,
     * which is precisely when no cursor is issued.
     */
    private static String nextCursor(List<IssueEntity> read, int limit) {
        if (read.size() < limit) {
            return null;
        }
        IssueEntity last = read.getLast();
        return last.getTriagedAt() == null
                ? null
                : new RegisterCursor(last.getTriagedAt(), String.valueOf(last.getId())).encoded();
    }

    private static Optional<Long> asId(String value) {
        try {
            return Optional.of(Long.parseLong(value));
        } catch (NumberFormatException unreadable) {
            return Optional.empty();
        }
    }

    /**
     * One row, or nothing when the caller may not see the issue it describes.
     *
     * <p>Narrowed here rather than in the query, by {@code permits} — the single implementation of
     * that question.
     *
     * <p><b>The decision fields come from the issue, the dates from its history.</b> The issue
     * carries the exception as it stands now; the history says when it was granted and when it was
     * last revisited. Reading the decision from the history instead — which is what the first
     * version did — is what produced a register listing exceptions that had since been withdrawn.
     */
    private static ExceptionEntry entry(
            IssueEntity issue,
            List<TriageEventEntity> history,
            TargetNaming.Names names,
            Visibility allowed,
            Instant now) {

        ScanTarget target = issue.getRepoId() != null
                ? new ScanTarget.Repository(issue.getRepoId())
                : new ScanTarget.Container(issue.getContainerId());
        if (!allowed.permits(target)) {
            return null;
        }

        // Oldest first, so the last match of each kind is the current one.
        TriageEventEntity granted = null;
        TriageEventEntity reviewed = null;
        for (TriageEventEntity event : history) {
            if (REVIEW.equals(event.getOrigin())) {
                reviewed = event;
            } else if (issue.getTriageStatus() != null
                    && issue.getTriageStatus().equals(event.getToStatus())) {
                granted = event;
            }
        }

        boolean lapsed = issue.getTriageExpiresAt() != null && issue.getTriageExpiresAt().isBefore(now);
        return new ExceptionEntry(
                issue.getId(),
                issue.getIdentifier(),
                issue.getSeverity(),
                issue.getRepoId() != null ? "REPOSITORY" : "CONTAINER",
                issue.getRepoId() != null ? issue.getRepoId() : issue.getContainerId(),
                names.of(issue.getRepoId(), issue.getContainerId()),
                issue.getTriageStatus(),
                issue.getTriageJustification(),
                issue.getTriageComment(),
                issue.getTriagedBy(),
                granted == null ? null : granted.getOrigin(),
                issue.getTriagedAt(),
                issue.getTriageExpiresAt(),
                lapsed,
                reviewed == null ? null : reviewed.getOccurredAt(),
                reviewed == null ? null : reviewed.getActor());
    }
}
