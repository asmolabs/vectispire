package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.time.Instant;
import java.util.Map;

/**
 * The backlog's filters: what a query over the issues asks, never how.
 *
 * <p><b>One definition, used by the page and by its count.</b> Two separately built queries end
 * up disagreeing, and the symptom is a pagination announcing pages the list does not contain. The
 * predicate is built from these in one place, {@code IssueSpecifications}, beside the repository.
 *
 * <p><b>Criteria, not a specification, since step 5.</b> This record built the JPA specification
 * itself, and the modules that read the backlog — the dashboard, the compliance figures, the exports
 * — built one from it and composed it with predicates of their own, naming the issue entity to do so.
 * They hand these criteria to {@code IssueCatalog} now; the two conditions they used to add by hand
 * are criteria too ({@link #touching}, {@link #onlyCves}), so the entity stays {@code issues}'
 * (decision 0029).
 *
 * @param onlyDirect restricts to declared dependencies. <b>It only acts on {@code true}</b>:
 *     "show transitive ones too" is the default, and filtering on {@code false} would hide the
 *     issues whose nature is unknown — the majority on any target with no dependency graph
 * @param onlyKev restricts to actively exploited vulnerabilities, and like {@code onlyDirect}
 *     acts on {@code true} alone. The dashboard has always linked to this filter; nothing read
 *     it, so the most actionable figure on the screen opened the entire backlog
 */
public record IssueFilters(
        String state,
        String severity,
        String type,
        String triageStatus,
        Long repoId,
        Long containerId,
        boolean onlyDirect,
        boolean onlyKev,
        String search,
        boolean excludeSettled,
        Map<Severity, Instant> overdueBefore,
        Visibility visibility,
        Instant touchingSince,
        boolean cveOnly) {

    /** Everything the caller asked for, seen by somebody the deployment does not restrict. */
    public IssueFilters(
            String state,
            String severity,
            String type,
            String triageStatus,
            Long repoId,
            Long containerId,
            boolean onlyDirect,
            boolean onlyKev,
            String search) {
        this(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                false, Map.of(), Visibility.everything(), null, false);
    }

    /** The nine filters a request can carry, with the visibility resolved for its caller. */
    public IssueFilters(
            String state,
            String severity,
            String type,
            String triageStatus,
            Long repoId,
            Long containerId,
            boolean onlyDirect,
            boolean onlyKev,
            String search,
            Visibility visibility) {
        this(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                false, Map.of(), visibility, null, false);
    }

    /** Every filter but the two that only readers outside the backlog's screens add. */
    public IssueFilters(
            String state,
            String severity,
            String type,
            String triageStatus,
            Long repoId,
            Long containerId,
            boolean onlyDirect,
            boolean onlyKev,
            String search,
            boolean excludeSettled,
            Map<Severity, Instant> overdueBefore,
            Visibility visibility) {
        this(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                excludeSettled, overdueBefore, visibility, null, false);
    }

    /**
     * The issues that can affect a trend window, and no others.
     *
     * <p>This is {@code PostureTrendAnalytics.touchesWindow} written as a query, and the two have
     * to say the same thing: an issue resolved before the window opened cannot appear in any of
     * its days' backlogs, cannot be newly discovered in it and cannot be newly resolved in it.
     * The last clause covers a row whose resolution precedes its first sighting — nonsense that
     * exists in real data, and which the unfiltered engine still counts as opened in the window.
     *
     * <p>It narrows the filters it is added to, visibility included, and never replaces them: a
     * narrowing predicate can never be mistaken for an authorising one.
     */
    public IssueFilters touching(Instant windowStart) {
        return new IssueFilters(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                excludeSettled, overdueBefore, visibility, windowStart, cveOnly);
    }

    /**
     * The issues whose identifier is a CVE, and no others — what the VEX, CSAF and CycloneDX documents
     * describe. Matched case-insensitively on the {@code CVE-} prefix, as the documents did in the
     * predicate they added to these filters.
     */
    public IssueFilters onlyCves() {
        return new IssueFilters(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                excludeSettled, overdueBefore, visibility, touchingSince, true);
    }
}
