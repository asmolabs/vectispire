package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.access.web.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.audit.AuditEntryView;
import com.asmolabs.vectispire.core.audit.AuditLogQueryService;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** The audit trail, and its integrity. Administrators and CISOs. */
@RestController
@RequestMapping("/api/v1/audit-log")
@RequiresGovernanceRead
public class AuditLogController {

    private final AuditLogQueryService trail;

    public AuditLogController(AuditLogQueryService trail) {
        this.trail = trail;
    }

    public record AuditLogPage(List<AuditEntryView> items, long total, int limit, int offset) {}

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

    /** {@code limit}/{@code offset} as on {@code /issues}, clamped by the service. */
    @GetMapping
    public AuditLogPage list(
            @RequestParam(name = "operation_type", required = false) String operationType,
            @RequestParam(name = "user_id", required = false) String userId,
            @RequestParam(required = false) String search,
            @RequestParam(required = false, defaultValue = "50") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset) {

        AuditLogQueryService.Entries page = trail.page(operationType, userId, search, limit, offset);
        return new AuditLogPage(page.items(), page.total(), page.limit(), page.offset());
    }

    /** The values actually present, so the filter offers nothing empty. */
    @GetMapping("/operation-types")
    public List<String> operationTypes() {
        return trail.operationTypes();
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
        AuditLogQueryService.Integrity integrity = trail.verify();
        return new Verification(
                integrity.total(),
                integrity.unverifiable(),
                integrity.verified(),
                integrity.intact(),
                integrity.broken(),
                integrity.mirrored(),
                integrity.missingFromTable(),
                integrity.missingFromMirror());
    }
}
