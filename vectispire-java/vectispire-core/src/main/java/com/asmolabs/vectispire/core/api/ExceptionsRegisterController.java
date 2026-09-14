package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import com.asmolabs.vectispire.core.services.TargetNaming;
import com.asmolabs.vectispire.core.services.VisibilityService;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.data.domain.Limit;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * What somebody decided not to fix, and under what terms.
 *
 * <h2>Why this is a screen of its own</h2>
 *
 * <p><b>It is the question an assessor asks first, and the one a dashboard never answers.</b>
 * Every other view describes what the estate contains. This one describes what was argued away —
 * and a green backlog means two very different things depending on which of the two produced it.
 *
 * <p>The data has existed all along: every triage decision is written, with its author, its
 * justification and its expiry, and a second person has to approve one when four-eyes is on. What
 * was missing is the view — so the register could only be read one issue at a time, by somebody
 * who already knew which issue to open.
 *
 * <h2>What it shows, and what it deliberately does not</h2>
 *
 * <p>Two kinds of decision: the exemptions granted, and the ones awaiting approval. Not the
 * fixes. An issue closed because it was repaired is not an exception, and folding the two
 * together would bury the handful of rows that matter under every resolution the estate has ever
 * made.
 *
 * <p><b>A lapsed exemption is flagged rather than dropped.</b> One that expired last week and has
 * not been renewed is the most interesting row in the register: the risk was accepted for a
 * period, the period is over, and nobody has looked since.
 */
@Tag(name = "Exceptions", description = "The register of risk acceptances and dismissals")
@RestController
@RequestMapping("/api/v1/exceptions")
@RequiresAccount
public class ExceptionsRegisterController {

    /** Past this, a register is exported rather than read. */
    private static final int MAX_ENTRIES = 500;

    private final TriageEvents events;
    private final Issues issues;
    private final TargetNaming naming;
    private final VisibilityService visibility;
    private final Clock clock;

    public ExceptionsRegisterController(
            TriageEvents events,
            Issues issues,
            TargetNaming naming,
            VisibilityService visibility,
            Clock clock) {
        this.events = events;
        this.issues = issues;
        this.naming = naming;
        this.visibility = visibility;
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

    @Operation(summary = "The exceptions register", description = "Risk acceptances and dismissals, newest first, narrowed to what the caller may see.")
    @ApiResponse(responseCode = "200", description = "Register returned")
    @GetMapping
    public Register register(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(required = false, defaultValue = "200") int limit) {

        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        int capped = Math.clamp(limit, 1, MAX_ENTRIES);

        List<TriageEventEntity> decisions = events.findDecisions(
                List.of(TriageStatus.NOT_AFFECTED.wireName(), TriageStatus.PENDING_APPROVAL.wireName()),
                Limit.of(capped));

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
