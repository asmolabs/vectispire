package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.InvalidTriageException;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Period;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * What a person decides about an issue through the API: a triage, the same triage on many, a
 * ticket attached.
 *
 * <p><b>Each decision is checked, written and audited here, in that order.</b> The order is the
 * point: visibility before the write, so a hidden issue is refused rather than modified and then
 * refused; the audit after it, so the trail records what happened rather than what was attempted.
 * The transitions themselves belong to {@link IssueTriageService}; this class decides who may
 * make them and records that they did.
 *
 * <p>No transaction of its own, as the routes had none: each write below commits on its own, and
 * the audit entry follows it. Wrapping both would change what a failed audit write undoes.
 */
@Service
public class IssueDecisionService {

    /**
     * The same ceiling as the list route returns.
     *
     * <p>Deliberately equal: a screen that can show 500 rows can decide on 500 rows, and a limit
     * below what the list hands back would make "select all" an action the interface offers and
     * the API refuses.
     */
    private static final int MAX_BULK_TRIAGE = IssueQueryService.MAX_PAGE_SIZE;

    /** What the column accepts: a longer reference would be truncated by the database. */
    private static final int MAX_TICKET_REFERENCE = 64;

    private static final int MAX_TICKET_URL = 500;

    private final Issues issues;
    private final IssueTriageService triage;
    private final AuditLogService audit;
    private final SettingsService settings;

    public IssueDecisionService(
            Issues issues, IssueTriageService triage, AuditLogService audit, SettingsService settings) {
        this.issues = issues;
        this.triage = triage;
        this.audit = audit;
        this.settings = settings;
    }

    /**
     * Who is deciding, what they may see, and where the request came from for the audit trail.
     *
     * @param user absent for a caller that is not an account — an agent key
     */
    public record Caller(Optional<UserEntity> user, Visibility visibility, String ipAddress, String userAgent) {

        String actor() {
            return user.map(UserEntity::getUsername).orElse("unknown");
        }
    }

    /** A triage decision as the request spells it: wire names, and a review delay in days. */
    public record Decision(String status, String justification, String comment, Integer expiresInDays) {

        Triage.Request toRequest(String actor) {
            return new Triage.Request(
                    TriageStatus.fromWireName(status).orElse(null),
                    actor,
                    VexJustification.fromWireName(justification).orElse(null),
                    comment,
                    expiresInDays == null ? null : Period.ofDays(expiresInDays));
        }
    }

    /** A reference or URL the ticket columns cannot hold, worded for the person who typed it. */
    public static final class InvalidTicketException extends RuntimeException {
        InvalidTicketException(String message) {
            super(message);
        }
    }

    /**
     * Records one triage decision.
     *
     * @throws java.util.NoSuchElementException absent and hidden alike — see {@code Visibilities}
     */
    public IssueEntity triage(long id, Decision decision, Caller caller) {
        String actor = caller.actor();
        boolean canApprove = canApprove(caller);
        // Checked before the write, and 404 rather than 403.
        RowVisibility.requireVisible(issues.findById(id).orElse(null), caller.visibility());
        IssueEntity issue = triage.triage(id, decision.toRequest(actor), canApprove);

        // A triage can dismiss a finding: that is a security decision, and it belongs in the
        // audit trail as much as a role change does.
        audit.record(new AuditLogService.Record(
                AuditOperation.ISSUE_TRIAGED,
                String.valueOf(id),
                "Triage \"" + issue.getTriageStatus() + "\""
                        + (issue.getTriageJustification() == null ? "" : " (" + issue.getTriageJustification() + ")"),
                actor,
                caller.ipAddress(),
                caller.userAgent()));

        return issue;
    }

    /**
     * The same decision on many issues.
     *
     * <p><b>Every identifier is checked before the first one is written.</b> Checking as it goes
     * would let a batch containing one invisible issue triage the ones before it and then answer
     * 404 — a partial write reported as a failure, which is the worst of the two.
     *
     * @param decision may be null only when {@code ids} is empty, which is refused before it is read
     */
    public List<IssueEntity> triageMany(List<Long> ids, Decision decision, Caller caller) {
        if (ids.isEmpty()) {
            throw new InvalidTriageException("Select at least one issue to triage.");
        }
        // **Refused, not truncated.** Silently triaging the first 500 of 900 would report success
        // for a decision that did not reach 400 issues, and the caller has no way to see which.
        // The cap matches the list route's, so anything the screen can show, it can decide on.
        if (ids.size() > MAX_BULK_TRIAGE) {
            throw new InvalidTriageException(
                    "Too many issues at once: " + ids.size() + ", the limit is " + MAX_BULK_TRIAGE + ".");
        }

        String actor = caller.actor();
        boolean canApprove = canApprove(caller);
        for (Long id : ids) {
            RowVisibility.requireVisible(issues.findById(id).orElse(null), caller.visibility());
        }

        List<IssueEntity> triaged = triage.triageAll(ids, decision.toRequest(actor), canApprove);

        // **One entry for the action, not one per issue.** The audit log is never purged, and a
        // single dismissal of six hundred issues would bury every other entry around it. What is
        // lost is not traceability: each issue carries its own recorded transition in the triage
        // history, which is the document a compliance reader is handed. This entry says a bulk
        // decision happened, by whom, and how wide it was — which is what the audit log is for.
        audit.record(new AuditLogService.Record(
                AuditOperation.ISSUE_TRIAGED,
                ids.size() + " issues",
                "Bulk triage \"" + decision.status() + "\" on " + ids.size() + " issues"
                        + (decision.justification() == null ? "" : " (" + decision.justification() + ")")
                        + " — per-issue transitions are in each issue's triage history",
                actor,
                caller.ipAddress(),
                caller.userAgent()));

        return triaged;
    }

    /**
     * Attaches an existing ticket to a finding, onto the field the sweep and the inbound webhook
     * read — see {@code IssuesController#attachTicket} for why that field and not another.
     *
     * <p>The visibility check comes before the validation of the body, so a hidden or absent issue
     * answers 404 whatever was sent — the order the route has always had, and one a client may
     * already rely on.
     *
     * @throws java.util.NoSuchElementException absent and hidden alike
     * @throws InvalidTicketException a reference missing or too long, a URL too long
     */
    public IssueEntity attachTicket(long id, String rawReference, String rawUrl, Caller caller) {
        IssueEntity issue = RowVisibility.requireVisible(issues.findById(id).orElse(null), caller.visibility());

        String reference = rawReference == null ? "" : rawReference.trim();
        if (reference.isEmpty()) {
            throw new InvalidTicketException("A ticket reference is required.");
        }
        if (reference.length() > MAX_TICKET_REFERENCE) {
            throw new InvalidTicketException(
                    "That reference is longer than " + MAX_TICKET_REFERENCE + " characters.");
        }
        String url = rawUrl == null || rawUrl.isBlank() ? null : rawUrl.trim();
        if (url != null && url.length() > MAX_TICKET_URL) {
            throw new InvalidTicketException("That URL is longer than " + MAX_TICKET_URL + " characters.");
        }

        String previous = issue.getTicketRef();
        issues.attachTicket(id, reference, url);

        // Recorded as a decision, because it is one: the tracker's webhook can now close this
        // finding, and replacing the reference changes who holds that power.
        audit.record(new AuditLogService.Record(
                AuditOperation.ISSUE_TRIAGED,
                String.valueOf(id),
                previous == null
                        ? "Ticket " + reference + " attached"
                        : "Ticket reference changed from " + previous + " to " + reference,
                caller.actor(),
                caller.ipAddress(),
                caller.userAgent()));

        return issues.findById(id).orElseThrow();
    }

    /**
     * Four-eyes: with approval required, only a role that may approve settles a dismissal
     * directly; anybody else's lands as pending. A caller that is not an account keeps the
     * permissive answer it always had.
     */
    private boolean canApprove(Caller caller) {
        boolean fourEyesRequired = settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED);
        return !fourEyesRequired || caller.user()
                .flatMap(user -> Role.of(user.getRole()))
                .map(Role::canApproveTriage)
                .orElse(true);
    }
}
