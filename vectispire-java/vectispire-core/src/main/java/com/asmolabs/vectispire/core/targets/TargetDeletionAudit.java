package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.core.access.TargetGrants;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;

/**
 * The entries a target's deletion leaves: the deletion itself, saying what went with it, and one per
 * integration key it revoked.
 *
 * <p><b>Why one per key.</b> The keys restricted to a deleted target were revoked with it and nothing
 * said so: the key vanished from its owner's list, its pipeline began answering 401, and the log held
 * a repository deletion whose entry named no key. A key revoked by hand is an {@code API_KEY_DELETED}
 * entry under the key's id, which is where whoever runs the pipeline looks and what the SIEM hears as
 * a revocation; one revoked by a deletion is the same act, and is recorded the same way.
 *
 * <p>Written by the callers of {@link TargetDeletionService} once its transaction has committed — the
 * audit log opens its own, which on SQLite would wait on the deletion's file lock.
 */
final class TargetDeletionAudit {

    private TargetDeletionAudit() {}

    /**
     * @param what the target as the deletion's entry names it — "repository 12", "image 4"
     * @param description the deletion's entry, before the account of what went with it
     */
    static void record(
            AuditLogService audit, RequestActor actor, long targetId, String what, String description,
            TargetGrants.Revoked revoked) {
        AuditLogService.Record deleted = actor.entry(
                AuditOperation.SETTING_UPDATED, String.valueOf(targetId), description + " (" + revoked.summary() + ")");
        // A grant revoked is an access change nobody else will announce, as for a project's deletion.
        audit.record(revoked.grants() > 0 ? deleted.signalling(SecurityEventType.ACCESS_GRANT_CHANGED) : deleted);
        for (TargetGrants.RevokedKey key : revoked.keys()) {
            audit.record(actor.entry(
                    AuditOperation.API_KEY_DELETED,
                    key.id().toString(),
                    "API key revoked with its target: " + key.name() + " (restricted to " + what + ", deleted)"));
        }
    }
}
