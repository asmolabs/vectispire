package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
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
            boolean lapsed) {}

    /**
     * @param granted exemptions in force
     * @param awaitingApproval requested, not yet granted — the four-eyes queue
     * @param lapsed granted, expired, and not revisited. <b>The figure worth acting on</b>
     */
    public record Register(
            List<ExceptionEntry> entries,
            long granted,
            @JsonProperty("awaiting_approval") long awaitingApproval,
            long lapsed) {}

    /**
     * The register, newest first, narrowed to what the caller may see.
     *
     * <p><b>The cap bounds what is read, not what is returned.</b> Visibility is applied after the
     * read, by {@code permits} — a reader restricted to two repositories sees only their rows among
     * the most recent ones, rather than a page assembled in SQL from somebody else's.
     *
     * @param limit how many decisions to read; clamped to {@link #MAX_ENTRIES}
     * @param allowed the caller's allowance
     */
    @Transactional(readOnly = true)
    public Register register(int limit, Visibility allowed) {
        List<TriageEventEntity> decisions =
                events.findDecisions(DECISIONS, Limit.of(Math.clamp(limit, 1, MAX_ENTRIES)));

        Map<Long, IssueEntity> byId = issues
                .findAllById(decisions.stream().map(TriageEventEntity::getIssueId).distinct().toList())
                .stream()
                .collect(Collectors.toMap(IssueEntity::getId, Function.identity()));

        List<Long> repoIds = byId.values().stream()
                .map(IssueEntity::getRepoId)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        List<Long> containerIds = byId.values().stream()
                .map(IssueEntity::getContainerId)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        TargetNaming.Names names = naming.forIds(repoIds, containerIds);

        Instant now = clock.instant();
        List<ExceptionEntry> entries = decisions.stream()
                .map(event -> entry(event, byId.get(event.getIssueId()), names, allowed, now))
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
                entries.stream().filter(ExceptionEntry::lapsed).count());
    }

    /**
     * One row, or nothing when the caller may not see the issue it describes.
     *
     * <p>Narrowed here rather than in the query, by {@code permits} — the single implementation of
     * that question. An issue the store no longer holds yields nothing too: an exception naming a
     * deleted issue is a row about nothing.
     */
    private static ExceptionEntry entry(
            TriageEventEntity event,
            IssueEntity issue,
            TargetNaming.Names names,
            Visibility allowed,
            Instant now) {

        if (issue == null) {
            return null;
        }
        ScanTarget target = issue.getRepoId() != null
                ? new ScanTarget.Repository(issue.getRepoId())
                : new ScanTarget.Container(issue.getContainerId());
        if (!allowed.permits(target)) {
            return null;
        }

        boolean lapsed = event.getExpiresAt() != null && event.getExpiresAt().isBefore(now);
        return new ExceptionEntry(
                issue.getId(),
                issue.getIdentifier(),
                issue.getSeverity(),
                issue.getRepoId() != null ? "REPOSITORY" : "CONTAINER",
                issue.getRepoId() != null ? issue.getRepoId() : issue.getContainerId(),
                names.of(issue.getRepoId(), issue.getContainerId()),
                event.getToStatus(),
                event.getJustification(),
                event.getComment(),
                event.getActor(),
                event.getOrigin(),
                event.getOccurredAt(),
                event.getExpiresAt(),
                lapsed);
    }
}
