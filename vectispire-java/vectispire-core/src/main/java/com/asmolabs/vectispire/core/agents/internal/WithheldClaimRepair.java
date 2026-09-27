package com.asmolabs.vectispire.core.agents.internal;

import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.audit.AuditLogQueryService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Gives back, once per database, the attempts that withheld claims counted on scans never delivered.
 *
 * <p><b>The defect.</b> Until the claim of an agent that cannot be handed a delegated credential left
 * the scans needing one out of its selection, each of its polls took such a scan — the take counts an
 * attempt — found it could not deliver, and put it back without refunding: every few seconds, for as
 * long as the agent ran, since decision 0031 for an agent with no verified sealing key, and before it
 * for a delegated agent announcing no key over a link that did not count as encrypted. A scan nothing
 * had tried then reached an executor that could run it with its takeovers spent, and failed for good
 * as "lease exhausted" at its first lapsed lease.
 *
 * <p><b>What is proven, and what is not.</b> A withheld claim leaves no trace — no audit entry, no
 * result, and the put-back clears the claim's columns — so no count can be split into real and
 * fictitious attempts. What leaves a trace is a real delivery of a credential: {@code
 * AGENT_CREDENTIAL_SENT}, naming the scan. The rule is therefore the conservative one: a scan still
 * <em>waiting</em>, of a repository that carries a credential, whose credential never left for any
 * agent, with an attempt counted, has its attempts set back to zero — and only on a database where an
 * agent in {@code delegated} mode is declared, since no other agent ever reached the withheld path.
 * The imprecision accepted: on such a scan, a real attempt that also leaves no trace — the built-in
 * worker or a {@code local} agent that died mid-scan, a poll that hung up before its answer — is given
 * back too, which costs a jamming target at most the policy's takeovers again. Left untouched: a scan
 * delivered with its credential at least once (its count mixes both kinds), a scan running, completed
 * or failed — one failed for good by the inflated count stays failed, and is run again by hand — an
 * image scan, a repository without a credential, and a database whose delegated agent has since been
 * deleted.
 *
 * <p><b>Not a migration.</b> A Flyway migration runs on every installation, those that never had the
 * defect included, and the rule above is not provably right everywhere; it also cannot write the audit
 * entry, whose hash chain is computed here. <b>Once, and the audit entry is the bookkeeping</b>, as
 * the weekly digest's is: the repair runs while no {@link AuditOperation#SCAN_ATTEMPTS_REPAIRED} entry
 * exists, writes one whatever it repaired, and never runs again — a later restart must not give back
 * the attempts of a scan that is genuinely jamming its workers. Two instances starting together may
 * both run it: the refund is conditional and the second finds nothing left, at the price of a second
 * entry saying so.
 */
@Component
public class WithheldClaimRepair {

    private static final Logger log = LoggerFactory.getLogger(WithheldClaimRepair.class);

    /** The audit column's width: past it the trail truncates, and a cut identifier would name another scan. */
    static final int DESCRIPTION_LENGTH = 255;

    private final AgentRepository agents;
    private final ScanCatalog scans;
    private final TargetCatalog targets;
    private final AuditLogQueryService trail;
    private final AuditLogService audit;

    public WithheldClaimRepair(
            AgentRepository agents,
            ScanCatalog scans,
            TargetCatalog targets,
            AuditLogQueryService trail,
            AuditLogService audit) {
        this.agents = agents;
        this.scans = scans;
        this.targets = targets;
        this.trail = trail;
        this.audit = audit;
    }

    /** What one call did: nothing because it had run before, or the scans whose attempts it gave back. */
    public sealed interface Outcome {

        record AlreadyDone() implements Outcome {}

        record Repaired(List<Long> scans) implements Outcome {}
    }

    /** At start, and never in the way of it: a repair that fails is logged and tried at the next start. */
    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        try {
            repairOnce();
        } catch (RuntimeException failed) {
            log.warn("The repair of the attempts counted by withheld claims did not run: {}", failed.getMessage());
        }
    }

    public Outcome repairOnce() {
        if (trail.countSince(AuditOperation.SCAN_ATTEMPTS_REPAIRED.name(), Instant.EPOCH) > 0) {
            return new Outcome.AlreadyDone();
        }

        List<Long> repaired = delegatedAgentDeclared() ? refundUndelivered() : List.of();
        audit.record(AuditLogService.Record.of(
                AuditOperation.SCAN_ATTEMPTS_REPAIRED,
                "scans",
                describe(repaired),
                // No actor: nobody asked for this, and a "system" user would put a person who does not
                // exist into the trail an assessor reads — the digest and the triage expiry say the same.
                null));
        if (!repaired.isEmpty()) {
            log.info("{} waiting scan(s) had the attempts of withheld claims given back: {}", repaired.size(),
                    listed(repaired));
        }
        return new Outcome.Repaired(repaired);
    }

    private boolean delegatedAgentDeclared() {
        return agents.findAll().stream()
                .anyMatch(agent -> CredentialsMode.byWireName(agent.getCredentialsMode())
                        .filter(mode -> mode == CredentialsMode.DELEGATED)
                        .isPresent());
    }

    private List<Long> refundUndelivered() {
        List<ScanCatalog.AttemptedScan> waiting = scans.waitingWithAttempts();
        if (waiting.isEmpty()) {
            return List.of();
        }
        Set<Long> carrying = targets.carryingCredentials(
                waiting.stream().map(ScanCatalog.AttemptedScan::repoId).collect(Collectors.toSet()));
        List<Long> candidates = waiting.stream()
                .filter(scan -> carrying.contains(scan.repoId()))
                .map(ScanCatalog.AttemptedScan::id)
                .sorted()
                .toList();
        if (candidates.isEmpty()) {
            return List.of();
        }
        Set<String> delivered = trail.resourcesNamed(
                AuditOperation.AGENT_CREDENTIAL_SENT.name(),
                candidates.stream().map(String::valueOf).toList());
        List<Long> undelivered = candidates.stream().filter(id -> !delivered.contains(String.valueOf(id))).toList();
        if (undelivered.isEmpty()) {
            return List.of();
        }
        scans.refundAttempts(undelivered);
        return undelivered;
    }

    /**
     * The entry, within the column's width: the count always, the identifiers as many as fit whole.
     * The log line lists them all.
     */
    static String describe(List<Long> repaired) {
        if (repaired.isEmpty()) {
            return "Upgrade check: no waiting scan carried attempts counted by claims withheld from a delegated agent.";
        }
        StringBuilder text = new StringBuilder("Upgrade repair: attempts reset to 0 on " + repaired.size()
                + " waiting scan(s) whose credential no agent was ever handed, counted by withheld claims. Scans: ");
        for (int i = 0; i < repaired.size(); i++) {
            String next = (i == 0 ? "" : ", ") + repaired.get(i);
            String rest = i + 1 < repaired.size() ? " and " + (repaired.size() - i - 1) + " more." : ".";
            if (text.length() + next.length() + rest.length() > DESCRIPTION_LENGTH) {
                return text.append(" and ").append(repaired.size() - i).append(" more.").toString();
            }
            text.append(next);
        }
        return text.append('.').toString();
    }

    private static String listed(List<Long> ids) {
        return ids.stream().map(String::valueOf).collect(Collectors.joining(", "));
    }
}
