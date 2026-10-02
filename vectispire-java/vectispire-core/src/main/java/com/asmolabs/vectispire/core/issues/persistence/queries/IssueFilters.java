package com.asmolabs.vectispire.core.issues.persistence.queries;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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
 * @param targetsWithin the repositories and images of a project or a solution, as their owner listed
 *     them at the moment of asking, or null for no such narrowing. <b>An empty set matches nothing</b>:
 *     a project holding no target has no issue, and reading "none" as "no filter" would answer the
 *     whole backlog for it. It narrows and never authorises — the visibility is applied beside it — and
 *     the predicate built from it writes its identifiers into the statement rather than binding them,
 *     since a project is sized by the data ({@code IssueSpecifications}). Targets rather than
 *     repository identifiers since an image can be filed in a project (amendment of 2026-09-30 to
 *     decision 0023): a repository and an image may carry the same number, and each is matched by its
 *     own column
 * @param owaspCategory the issues the OWASP grid places in this category ({@code A01}…{@code A10}),
 *     by {@code OwaspCoverage.placementOf} — a vulnerability is {@code A06} with no column — or null for
 *     no such narrowing
 * @param lifetime the dates an issue's life must cross, or null for none
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
        boolean cveOnly,
        Set<ScanTarget> targetsWithin,
        String owaspCategory,
        Lifetime lifetime) {

    public IssueFilters {
        targetsWithin = targetsWithin == null ? null : Set.copyOf(targetsWithin);
    }

    /**
     * What an issue's dates must say — the backlog's drill-down from the weekly OWASP view. Every
     * bound is an instant, every interval half open ({@code from} included, {@code before} excluded),
     * and each is optional: null asks nothing.
     *
     * @param openAt open at this instant: first seen before it, not resolved before it, and not inside an
     *     earlier resolution a reopening recorded — the rule the weekly view reconstructs a week's end
     *     with, and with its limit: a reopening older than V68 recorded nothing, and such an issue keeps
     *     only its latest resolution
     * @param resolvedFrom with {@code resolvedBefore}, resolved within: its latest resolution, or an
     *     earlier one a reopening recorded
     */
    public record Lifetime(
            Instant openAt, Instant firstSeenFrom, Instant firstSeenBefore, Instant resolvedFrom, Instant resolvedBefore) {

        /** Whether anything is asked at all. */
        public boolean asksAnything() {
            return openAt != null || firstSeenFrom != null || firstSeenBefore != null
                    || resolvedFrom != null || resolvedBefore != null;
        }
    }

    /** Every criterion but the two the backlog's drill-down adds. */
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
            Visibility visibility,
            Instant touchingSince,
            boolean cveOnly,
            Set<ScanTarget> targetsWithin) {
        this(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                excludeSettled, overdueBefore, visibility, touchingSince, cveOnly, targetsWithin, null, null);
    }

    /** Every criterion but the narrowing to a project's or a solution's targets. */
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
            Visibility visibility,
            Instant touchingSince,
            boolean cveOnly) {
        this(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                excludeSettled, overdueBefore, visibility, touchingSince, cveOnly, null);
    }

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
                excludeSettled, overdueBefore, visibility, windowStart, cveOnly, targetsWithin, owaspCategory, lifetime);
    }

    /**
     * The issues whose identifier is a CVE, and no others — what the VEX, CSAF and CycloneDX documents
     * describe. Matched case-insensitively on the {@code CVE-} prefix, as the documents did in the
     * predicate they added to these filters.
     */
    public IssueFilters onlyCves() {
        return new IssueFilters(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                excludeSettled, overdueBefore, visibility, touchingSince, true, targetsWithin, owaspCategory, lifetime);
    }

    /**
     * The issues of these targets and no others — a project's or a solution's repositories and images,
     * listed by {@code targets}, which owns the membership. Narrows what is already narrowed: called
     * twice, it keeps the targets both lists name, so a project within a solution it is not in matches
     * nothing.
     */
    public IssueFilters within(Collection<? extends ScanTarget> targets) {
        Set<ScanTarget> narrowed = Set.copyOf(targets);
        if (targetsWithin != null) {
            narrowed = narrowed.stream().filter(targetsWithin::contains).collect(Collectors.toUnmodifiableSet());
        }
        return new IssueFilters(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                excludeSettled, overdueBefore, visibility, touchingSince, cveOnly, narrowed, owaspCategory, lifetime);
    }

    /** The issues placed in this OWASP category, or every one when it is null. Replaces an earlier one. */
    public IssueFilters placedIn(String category) {
        return new IssueFilters(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                excludeSettled, overdueBefore, visibility, touchingSince, cveOnly, targetsWithin, category, lifetime);
    }

    /** The issues whose dates say what {@code asked} asks, or every one when it is null. Replaces an earlier one. */
    public IssueFilters living(Lifetime asked) {
        return new IssueFilters(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                excludeSettled, overdueBefore, visibility, touchingSince, cveOnly, targetsWithin, owaspCategory, asked);
    }
}
