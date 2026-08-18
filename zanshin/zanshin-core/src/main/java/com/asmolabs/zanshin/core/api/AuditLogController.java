package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.audit.AuditChain;
import com.asmolabs.zanshin.core.persistence.AuditLogEntity;
import com.asmolabs.zanshin.core.repositories.AuditLog;
import com.asmolabs.zanshin.core.services.AuditLogService;
import java.util.List;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** The audit trail, and its integrity. Administrators only. */
@RestController
@RequestMapping("/api/v1/audit-log")
@PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN')")
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
     */
    public record Verification(long total, int unverifiable, long verified, boolean intact, String broken) {}

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
        long total = entries.count();
        return new Verification(
                total,
                result.unverifiable(),
                total - result.unverifiable(),
                result.broken() == null,
                result.broken());
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
