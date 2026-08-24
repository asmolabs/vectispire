package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.gate.PolicyGate;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution.PolicyLookup;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution.ResolvedPolicy;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution.Scope;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution.StoredPolicy;
import com.asmolabs.vectispire.common.domain.gate.RequestedPolicy;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.tickets.Tickets;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.GatePolicies;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The sweep that opens tickets.
 *
 * <p><b>A sweep, not an event.</b> Notifications go out after a scan; tickets do not. A pass
 * over "actionable issues with no ticket" is idempotent by construction — the reference stored
 * on the issue <em>is</em> the deduplication key — so a tracker under maintenance is retried on
 * the next pass instead of silently losing the ticket. It is also why no outbox is needed here:
 * the state to reconcile is already in the issue's row.
 *
 * <p><b>The gate is evaluated issue by issue, deliberately.</b> Evaluating a target's whole
 * backlog and opening a ticket per violation would be the same query, but an issue's ticket
 * would then depend on which <em>other</em> issues happen to be open — and "why does this one
 * have a ticket and that one not" has to have an answer about the issue itself.
 */
@Service
public class TicketSweepService {

    private static final Logger log = LoggerFactory.getLogger(TicketSweepService.class);

    private static final String SCOPE_GLOBAL = "global";
    private static final String SCOPE_REPOSITORY = "repository";
    private static final String SCOPE_CONTAINER = "container";

    private final Issues issues;
    private final GatePolicies policies;
    private final TargetNaming names;
    private final TicketService tickets;
    private final AuditLogService audit;

    public TicketSweepService(
            Issues issues,
            GatePolicies policies,
            TargetNaming names,
            TicketService tickets,
            AuditLogService audit) {
        this.issues = issues;
        this.policies = policies;
        this.names = names;
        this.tickets = tickets;
        this.audit = audit;
    }

    /** One pass. Returns how many tickets were opened. */
    public int sweep() {
        return sweep(Tickets.MAX_TICKETS_PER_SWEEP);
    }

    /**
     * <b>Not one transaction for the pass</b>, for two reasons that happen to agree.
     *
     * <p>The first is behaviour: each issue is settled on its own, so a tracker that starts
     * refusing at the twelfth ticket does not undo the eleven already opened — they would all be
     * attempted again next pass, and a tracker does not deduplicate what it has already created.
     *
     * <p>The second is that a transaction here breaks SQLite outright. The audit entry is written
     * {@code REQUIRES_NEW}, deliberately, so that the attempt survives a rollback; on an engine
     * where the lock is the whole database file, that second connection waits for the first —
     * which is this one — and the pass deadlocks against itself. Found by running it, on the one
     * engine the unit suite can reach.
     */
    public int sweep(int limit) {
        if (!tickets.isEnabled()) {
            return 0;
        }

        List<IssueEntity> candidates = issues.findActionableWithoutTicket(
                IssueState.OPEN.wireName(),
                List.of(TriageStatus.NOT_AFFECTED.wireName(), TriageStatus.FIXED.wireName()),
                Limit.of(limit));
        if (candidates.isEmpty()) {
            return 0;
        }

        Map<String, StoredPolicy> byScope = activePolicies();
        TargetNaming.Names targetNames = names.all();

        int created = 0;
        for (IssueEntity issue : candidates) {
            ResolvedPolicy resolved = PolicyResolution.resolve(
                    new PolicyLookup(
                            Optional.ofNullable(byScope.get(scopeOf(issue))),
                            Optional.ofNullable(byScope.get(SCOPE_GLOBAL + ":0"))),
                    RequestedPolicy.none(),
                    Scope.TARGET);

            if (PolicyGate.evaluate(List.of(IssueViews.forGate(issue)), resolved.policy()).passed()) {
                // Below the bar for this target: no ticket, and **no marker either** — the policy
                // can be tightened tomorrow, and the issue has to become a candidate again then.
                continue;
            }

            Optional<TicketService.Ticket> ticket = tickets.createForIssue(
                    IssueViews.forTicket(issue), targetNames.of(issue.getRepoId(), issue.getContainerId()));
            // Left without a reference on purpose: the next pass will try again.
            if (ticket.isEmpty()) {
                continue;
            }

            issues.attachTicket(issue.getId(), ticket.get().reference(), ticket.get().url());
            created++;

            audit.record(AuditLogService.Record.of(
                    AuditOperation.TICKET_CREATED,
                    String.valueOf(issue.getId()),
                    "Ticket " + ticket.get().reference() + " opened for "
                            + (issue.getIdentifier() == null ? issue.getType() : issue.getIdentifier())
                            + " (" + resolved.describeSource() + ")",
                    null));
        }

        if (created > 0) {
            log.info("{} ticket(s) opened.", created);
        }
        return created;
    }

    /**
     * An issue always belongs to a target in practice, but a row with neither must fall back to
     * the global policy rather than resolving a {@code container:null} scope — which would look
     * up nothing and quietly give that issue the built-in policy instead of the operator's.
     */
    private static String scopeOf(IssueEntity issue) {
        if (issue.getRepoId() != null) {
            return SCOPE_REPOSITORY + ":" + issue.getRepoId();
        }
        if (issue.getContainerId() != null) {
            return SCOPE_CONTAINER + ":" + issue.getContainerId();
        }
        return SCOPE_GLOBAL + ":0";
    }

    private Map<String, StoredPolicy> activePolicies() {
        Map<String, StoredPolicy> byScope = new HashMap<>();
        policies.findByIsActiveTrue().forEach(policy -> byScope.put(
                policy.getTargetKind() + ":" + (policy.getTargetId() == null ? 0 : policy.getTargetId()),
                IssueViews.storedPolicy(policy)));
        return byScope;
    }

}
