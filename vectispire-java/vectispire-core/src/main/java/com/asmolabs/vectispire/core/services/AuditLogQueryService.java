package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.core.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.repositories.AuditLog;
import java.util.List;
import java.util.Locale;
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

    public AuditLogQueryService(AuditLog entries, AuditLogService log) {
        this.entries = entries;
        this.log = log;
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
        return new Integrity(
                total,
                result.unverifiable(),
                total - result.unverifiable(),
                // **The chain holding is no longer the whole answer.** An entry the mirror has
                // and the table lost leaves the chain intact by construction, so reporting
                // `intact` on the chain alone would call a deletion a clean bill of health.
                result.broken() == null && mirror.missingFromTable() == 0,
                result.broken(),
                mirror.configured(),
                mirror.missingFromTable(),
                mirror.missingFromMirror());
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
