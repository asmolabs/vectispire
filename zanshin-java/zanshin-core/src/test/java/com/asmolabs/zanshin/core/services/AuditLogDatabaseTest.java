package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.zanshin.common.domain.audit.AuditChain;
import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.core.ZanshinContextTest;
import com.asmolabs.zanshin.core.persistence.AuditLogEntity;
import com.asmolabs.zanshin.core.repositories.AuditLog;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The audit chain against a database.
 *
 * <p>The unit suite proves the chaining with a fake that returns rows in the order it was given
 * them. A database returns them in the order the query asks for, which is the whole question:
 * the chain is built in one order and verified in another, and a mistake there declares a
 * perfectly intact log broken.
 */
@DisplayName("the audit chain, against a database")
class AuditLogDatabaseTest extends ZanshinContextTest {

    @Autowired
    private AuditLogService audit;

    @Autowired
    private AuditLog entries;

    @Autowired
    private TransactionTemplate transactions;

    @Test
    @DisplayName("a burst of entries verifies, read back through the query")
    void aBurstVerifies() {
        for (int i = 0; i < 20; i++) {
            audit.record(AuditLogService.Record.of(
                    AuditOperation.SETTING_UPDATED, "sast_enabled", "changed " + i, "alice"));
        }

        assertThat(entries.count()).isEqualTo(20);
        assertThat(audit.verify()).returns(null, AuditChain.Verification::broken);
    }

    @Test
    @DisplayName("an entry altered in the table is detected")
    void tamperingIsDetected() {
        audit.record(AuditLogService.Record.of(AuditOperation.USER_DELETED, "bob", "Account deleted", "alice"));
        audit.record(AuditLogService.Record.of(AuditOperation.LOGIN_SUCCESS, "alice", "Login succeeded", "alice"));

        AuditLogEntity first = entries.findAllByOrderByTimestampAscIdAsc().getFirst();
        first.setDescription("Account archived");
        entries.save(first);

        assertThat(audit.verify().broken()).isNotNull();
    }

    @Test
    @DisplayName("an entry survives the rollback of the action it describes")
    void theRecordOutlivesAFailedAction() {
        assertThatThrownBy(() -> transactions.executeWithoutResult(status -> {
                    audit.record(AuditLogService.Record.of(
                            AuditOperation.ISSUE_TRIAGED, "42", "Dismissed", "alice"));
                    throw new IllegalStateException("the triage violated a constraint");
                }))
                .isInstanceOf(IllegalStateException.class);

        // `REQUIRES_NEW`, executed. The attempt is exactly what an auditor wants to see, and
        // joining the caller's transaction would erase the record of everything that failed.
        assertThat(entries.count()).isEqualTo(1);
    }

    @Test
    @DisplayName("the rebuild makes a log of foreign entries verify again")
    void theRebuildRepairsAMigratedLog() {
        audit.record(AuditLogService.Record.of(AuditOperation.USER_CREATED, "bob", "Created", "alice"));
        audit.record(AuditLogService.Record.of(AuditOperation.USER_UPDATED, "bob", "Renamed", "alice"));

        AuditLogEntity second = entries.findAllByOrderByTimestampAscIdAsc().get(1);
        second.setEntryHash("a hash computed by another implementation");
        entries.save(second);
        assertThat(audit.verify().broken()).isNotNull();

        assertThat(audit.rebuild()).isEqualTo(2);
        assertThat(audit.verify()).returns(null, AuditChain.Verification::broken);
    }
}
