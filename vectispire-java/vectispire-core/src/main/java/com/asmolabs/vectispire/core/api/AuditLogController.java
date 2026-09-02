package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.core.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.repositories.AuditLog;
import com.asmolabs.vectispire.core.services.AuditLogService;
import java.util.List;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import com.asmolabs.vectispire.core.api.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** The audit trail, and its integrity. Administrators and CISOs. */
@RestController
@RequestMapping("/api/v1/audit-log")
@RequiresGovernanceRead
public class AuditLogController {

    private static final int DEFAULT_PAGE_SIZE = 50;
    private static final int MAX_PAGE_SIZE = 200;

    private final AuditLog entries;
    private final AuditLogService service;

    public AuditLogController(AuditLog entries, AuditLogService service) {
        this.entries = entries;
        this.service = service;
    }

    public record Page(List<AuditLogEntity> items, long total, int limit, int offset) {}

    /**
     * @param unverifiable entries predating the chaining: neither a proof nor an alarm, a fact
     * @param broken the first break, or {@code null} when the chain holds
     * @param mirrored whether a second copy outside this database is configured at all. Reported
     *     rather than hidden: "nothing missing" from a mirror that does not exist reads as
     *     reassurance, and is not
     * @param missingFromTable entries the mirror holds and this table does not. <b>The case the
     *     chain is blind to</b> — deleting the last entry leaves a chain that still verifies,
     *     because nothing descends from what was removed
     * @param missingFromMirror entries this table holds and the mirror does not: written before
     *     the mirror existed, written while it could not be reached, or inserted by somebody who
     *     had the database and not the file
     */
    public record Verification(
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
    @GetMapping
    public Page list(
            @RequestParam(name = "operation_type", required = false) String operationType,
            @RequestParam(name = "user_id", required = false) String userId,
            @RequestParam(required = false) String search,
            @RequestParam(required = false, defaultValue = "50") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset) {

        int size = Math.clamp(limit, 1, MAX_PAGE_SIZE);
        int from = Math.max(offset, 0);

        var page = entries.findFiltered(
                blankToNull(operationType),
                blankToNull(userId),
                blankToNull(search) == null ? null : "%" + search.trim().toLowerCase(java.util.Locale.ROOT) + "%",
                PageRequest.of(from / Math.max(size, 1), size,
                        Sort.by(Sort.Order.desc("timestamp"), Sort.Order.desc("id"))));

        return new Page(page.getContent(), page.getTotalElements(), size, from);
    }

    /** The values actually present, so the filter offers nothing empty. */
    @GetMapping("/operation-types")
    public List<String> operationTypes() {
        return entries.distinctOperationTypes();
    }

    /**
     * Verifies the integrity chain, and <b>says so on the screen</b>.
     *
     * <p>The chaining existed from the start and was only checkable by a script. An audit log
     * whose integrity nobody ever looks at mostly protects the conscience of whoever wrote it:
     * the verification is worth something only if its result is visible without effort.
     */
    @GetMapping("/verify")
    public Verification verify() {
        AuditChain.Verification result = service.verify();
        AuditLogService.MirrorComparison mirror = service.verifyAgainstMirror();
        long total = entries.count();
        return new Verification(
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
