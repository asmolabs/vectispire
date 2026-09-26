package com.asmolabs.vectispire.core.services.audit;

import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.core.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.repositories.AuditLog;
import java.util.List;
import java.util.Locale;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

/**
 * Reading the audit trail and reporting its integrity.
 *
 * <p>Apart from {@link AuditLogService}, which writes the log and verifies the chain, because a
 * page of entries filtered for a screen is not something the writer needs to know about.
 */
@Service
public class AuditLogQueryService {

    private static final int MAX_PAGE_SIZE = 200;

    private final AuditLog entries;
    private final AuditLogService log;
    private final ApplicationEventPublisher events;

    public AuditLogQueryService(AuditLog entries, AuditLogService log, ApplicationEventPublisher events) {
        this.entries = entries;
        this.log = log;
        this.events = events;
    }

    /** @param limit and {@code offset} as actually applied, after clamping */
    public record Entries(List<AuditEntryView> items, long total, int limit, int offset) {}

    /** See the controller's {@code Verification} for what each figure means to a reader. */
    public record Integrity(
            long total,
            int unverifiable,
            long verified,
            boolean intact,
            String broken,
            boolean mirrored,
            int missingFromTable,
            int missingFromMirror) {}

    /**
     * {@code limit}/{@code offset} as on {@code /issues}.
     *
     * <p>One pagination convention across the API beats a local convenience, and the client's
     * page type relies on it.
     */
    public Entries page(String operationType, String userId, String search, int limit, int offset) {
        int size = Math.clamp(limit, 1, MAX_PAGE_SIZE);
        int from = Math.max(offset, 0);

        Page<AuditLogEntity> page = entries.findFiltered(
                blankToNull(operationType),
                blankToNull(userId),
                blankToNull(search) == null ? null : "%" + search.trim().toLowerCase(Locale.ROOT) + "%",
                PageRequest.of(from / Math.max(size, 1), size,
                        Sort.by(Sort.Order.desc("timestamp"), Sort.Order.desc("id"))));

        return new Entries(
                page.getContent().stream().map(AuditEntryView::of).toList(), page.getTotalElements(), size, from);
    }

    /** The values actually present, so the filter offers nothing empty. */
    public List<String> operationTypes() {
        return entries.distinctOperationTypes();
    }

    public Integrity verify() {
        AuditChain.Verification result = log.verify();
        AuditLogService.MirrorComparison mirror = log.verifyAgainstMirror();
        long total = entries.count();
        boolean intact = result.broken() == null && mirror.missingFromTable() == 0;
        if (!intact) {
            // **Sent every time a verification finds it, not once.** A SOC deduplicates; what it
            // cannot do is hear about a tampering that was reported to one screen and nowhere else.
            // The SIEM queues it in the outbox, which the tampering did not touch — and says where
            // the chain broke, so the alarm does not depend on the log it is about.
            //
            // **A plain event, heard synchronously, and deliberately not an after-commit one.** This
            // method opens no transaction: the two reads above each ran in their own read-only one,
            // closed by now. A `@TransactionalEventListener` published with no transaction active is
            // dropped without a word unless told otherwise — the alarm lost, which is the one outcome
            // this path exists to prevent. There is nothing to roll back either: a verification
            // writes nothing, and the event describes the table's state, not a change this call made.
            // The listener queues it in a transaction of its own and never throws, as the direct
            // call did.
            events.publishEvent(new AuditChainBroken(result.broken(), mirror.missingFromTable()));
        }
        return new Integrity(
                total,
                result.unverifiable(),
                total - result.unverifiable(),
                // **The chain holding is no longer the whole answer.** An entry the mirror has
                // and the table lost leaves the chain intact by construction, so reporting
                // `intact` on the chain alone would call a deletion a clean bill of health.
                intact,
                result.broken(),
                mirror.configured(),
                mirror.missingFromTable(),
                mirror.missingFromMirror());
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
