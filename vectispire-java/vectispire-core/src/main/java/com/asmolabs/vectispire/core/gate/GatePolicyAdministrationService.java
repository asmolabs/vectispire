package com.asmolabs.vectispire.core.gate;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.gate.GatePolicy;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.gate.GateService.PolicyScope;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicyEntity;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * Storing and removing gate policies, each one audited.
 *
 * <p><b>Audited, because a policy decides what fails a build.</b> {@code GATE_POLICY_UPDATED} was
 * in the enum from the beginning with nothing writing it; loosening a threshold is exactly the
 * change somebody has to be able to find afterwards.
 *
 * <p><b>A bean of its own rather than two more methods on {@link GateService}</b>, because the
 * writes there are {@code @Transactional} and the audit entry must follow their commit: it opens
 * its own transaction, and inside theirs it waits on the parent's lock on SQLite, where the lock is
 * the file. Calling {@code store} through {@code this} would bypass the proxy and drop the
 * transaction; calling it across beans keeps the boundary exactly where the route had it.
 */
@Service
public class GatePolicyAdministrationService {

    private final GateService gate;
    private final AuditLogService audit;

    public GatePolicyAdministrationService(GateService gate, AuditLogService audit) {
        this.gate = gate;
        this.audit = audit;
    }

    /** Stores a new version for the scope, attributed to the actor, and records what it now says. */
    public StoredGatePolicyView store(PolicyScope scope, GatePolicy policy, String note, RequestActor actor) {
        // The note is a `text` column: bounded like every stored text, so a paste past MySQL's
        // 64 KB is a 400 here rather than a 500 from the insert.
        BoundedText.within(note, BoundedText.TEXT_MAX, "The note");
        GatePolicyEntity stored = gate.store(scope, policy, note, actor.username());

        String what = scope.isGlobal() ? "the global policy" : scope.kind() + " " + scope.id();
        record(actor, scope, "Gate policy for " + what + " set to version " + stored.getVersion() + ": "
                + describe(policy) + ".");
        return StoredGatePolicyView.of(stored);
    }

    /**
     * Removes the scope's override, so it inherits again.
     *
     * @return whether there was one — nothing is audited when there was not, since nothing changed
     */
    public boolean clear(PolicyScope scope, RequestActor actor) {
        if (!gate.clear(scope)) {
            return false;
        }
        record(actor, scope, "Gate policy removed; the target inherits again.");
        return true;
    }

    private void record(RequestActor actor, PolicyScope scope, String description) {
        audit.record(actor.entry(AuditOperation.GATE_POLICY_UPDATED, scope.kind() + ":" + scope.id(), description));
    }

    private static String describe(GatePolicy policy) {
        List<String> parts = new ArrayList<>();
        parts.add("fail on "
                + (policy.failOnSeverity() == null ? "no severity" : policy.failOnSeverity().wireName()));
        if (policy.failOnKev()) {
            parts.add("fail on actively exploited");
        }
        if (policy.fixableOnly()) {
            parts.add("fixable only");
        }
        if (policy.includeTriaged()) {
            parts.add("triaged findings counted");
        }
        if (policy.includeAiReview()) {
            parts.add("model review counted");
        }
        if (policy.failOnUncoveredLanguages()) {
            parts.add("fail when no rule covers the target");
        }
        return String.join(", ", parts);
    }
}
