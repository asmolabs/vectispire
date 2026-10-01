package com.asmolabs.vectispire.core.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.audit.internal.AuditMirror;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * An audit entry and what its listeners write, against a database (decision 0033, lot 2).
 *
 * <p>The SIEM heard of an entry only after the entry's commit, in a transaction of its own — a stop
 * between the two lost the event, with nothing to send it again. The listeners now write in the
 * entry's transaction, and the old path stays as the fallback for a listener that fails there. Both
 * halves need a transaction manager to mean anything: an exception leaving a proxy that takes part
 * in the entry's transaction marks it rollback-only, and the fallback is what keeps the entry then.
 *
 * <p>The service is built here over the context's repositories and transaction manager with a
 * listener of the test's own, so the mechanism is seen without the SIEM's settings in the way —
 * {@code SiemSignalsRoutesTest} covers the events themselves, through the routes.
 */
@DisplayName("an audit entry and its listeners' writes, against a database")
class AuditListenerDatabaseTest extends VectispireContextTest {

    @Autowired
    private AuditLogRepository entries;

    @Autowired
    private OutboxService outbox;

    @Autowired
    private OutboxMessageRepository messages;

    @Autowired
    private PlatformTransactionManager transactions;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("what a listener writes commits in the entry's transaction, and the after-commit path is not taken")
    void aListenerWritesWithTheEntry() {
        Recording listener = new Recording(at -> outbox.enqueue(Map.of("at", at.toString()), OutboxService.TYPE_SCAN_DELTA));

        audit(listener).record(AuditLogService.Record.of(AuditOperation.LOGIN_BLOCKED, "alice", "Too many attempts", "alice"));

        assertThat(entries.findAll()).hasSize(1);
        assertThat(messages.findAll()).as("written inside the entry's transaction: `enqueue` is MANDATORY").hasSize(1);
        assertThat(listener.inTransaction).isEqualTo(1);
        assertThat(listener.afterCommit).as("never both for one entry").isZero();
    }

    @Test
    @DisplayName("a listener that fails in the entry's transaction costs neither the entry nor its event: both are written apart")
    void aFailingListenerFallsBackToAfterCommit() {
        // The failure leaves `OutboxService.enqueue`, a proxy taking part in the entry's transaction,
        // which marks it rollback-only — the shape of a real one, not a throw of the listener's own.
        Recording listener = new Recording(at -> outbox.enqueue("not an object", OutboxService.TYPE_SCAN_DELTA));

        audit(listener).record(AuditLogService.Record.of(AuditOperation.LOGIN_BLOCKED, "alice", "Too many attempts", "alice"));

        assertThat(entries.findAll()).as("the entry, written once, on its own").hasSize(1);
        assertThat(messages.findAll()).as("nothing of the aborted attempt").isEmpty();
        assertThat(listener.inTransaction).isEqualTo(1);
        assertThat(listener.afterCommit).as("the fallback heard of it after the commit").isEqualTo(1);
    }

    private AuditLogService audit(AuditLogService.Listener listener) {
        return new AuditLogService(entries, new AuditMirror.Disabled(), clock, List.of(listener), transactions);
    }

    /** A listener that writes what it is given in the transaction, and counts both calls. */
    private static final class Recording implements AuditLogService.Listener {

        private final java.util.function.Consumer<Instant> write;
        private int inTransaction;
        private int afterCommit;

        Recording(java.util.function.Consumer<Instant> write) {
            this.write = write;
        }

        @Override
        public void recordedInTransaction(AuditLogService.Record entry, Instant at) {
            inTransaction++;
            write.accept(at);
        }

        @Override
        public void recorded(AuditLogService.Record entry, Instant at) {
            afterCommit++;
        }
    }
}
