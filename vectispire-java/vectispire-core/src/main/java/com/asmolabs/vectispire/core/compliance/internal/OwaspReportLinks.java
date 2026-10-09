package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.compliance.OwaspReport;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.IssueQueryService;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueRows;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * What an OWASP report's screen links to: the backlog per category, and the issues per cited identifier.
 *
 * <p>Both are asked with the caller's visibility, which the issues' own criteria apply — the same
 * predicate as the backlog's list, so a reader is never shown a count of issues the list would hide
 * from them. The route has refused a repository they do not see before this runs; the criteria narrow
 * again rather than trusting that it did.
 */
@Service
public class OwaspReportLinks {

    private final IssueQueryService backlog;
    private final IssueCatalog issues;

    public OwaspReportLinks(IssueQueryService backlog, IssueCatalog issues) {
        this.backlog = backlog;
        this.issues = issues;
    }

    /**
     * Each category's count, as the backlog's list counts it for the query the screen's link carries.
     *
     * <p><b>The backlog's own count, not a second definition.</b> {@link IssueQueryService#count} builds
     * the criteria the list builds — open by default, settled triage left out, placed as the grid places —
     * so the number on the link and the length of the list cannot drift apart. Ten counts rather than one
     * grouped query: a grouped one would be a second placement rule, and the vulnerabilities placed in
     * A06 by their type rather than their column are where the two would first disagree.
     */
    public Map<String, Long> categoryFindings(long repositoryId, Visibility allowed) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String category : OwaspCoverage.CATEGORIES.keySet()) {
            counts.put(category, backlog.count(backlogOf(repositoryId, category), allowed));
        }
        return counts;
    }

    /**
     * Each identifier of the evidence, resolved to the repository's open issues carrying it now.
     *
     * <p><b>The evidence, never the prose.</b> The model's answer names identifiers too, and the model
     * invents some; it also repeats what a finding's description says, and a description is written by
     * the audited repository or an upstream rule author. Linking every CVE-looking string of the prose
     * would let either author mint links into the backlog that read as scanner findings — so the
     * candidates are what the review recorded it showed the model ({@code evidence_identifiers}), and a
     * citation outside them stays text. Matched exactly, as the evidence carried it: a substring would
     * let {@code CVE-2026-1} lead to {@code CVE-2026-12}.
     *
     * @param shown the identifiers the review recorded, or null when it recorded none (before V84)
     * @return null when {@code shown} is null — not recorded, rather than nothing to link
     */
    public Map<String, OwaspReport.IssueLink> issueLinks(long repositoryId, List<String> shown, Visibility allowed) {
        if (shown == null) {
            return null;
        }
        if (shown.isEmpty()) {
            return Map.of();
        }
        // The repository's open issues in two columns, read once and grouped here: the evidence holds up
        // to three hundred identifiers, and the review read the same open backlog whole to build it.
        Map<String, List<Long>> carrying = new HashMap<>();
        for (IssueRows.Identified issue : issues.rows(
                new IssueFilters(IssueState.OPEN.wireName(), null, null, null, repositoryId, null, false, false, null,
                        allowed),
                IssueRows.Identified.class)) {
            if (issue.identifier() != null) {
                carrying.computeIfAbsent(issue.identifier(), any -> new ArrayList<>()).add(issue.id());
            }
        }

        Map<String, OwaspReport.IssueLink> links = new LinkedHashMap<>();
        for (String identifier : shown) {
            List<Long> ids = carrying.get(identifier);
            if (ids != null && !ids.isEmpty()) {
                links.put(identifier, new OwaspReport.IssueLink(ids.size() == 1 ? ids.getFirst() : null, ids.size()));
            }
        }
        return links;
    }

    /** {@code GET /api/v1/issues?repository_id=…&owasp_category=…&unsettled=true}, as the backlog reads it. */
    private static IssueQueryService.BacklogQuery backlogOf(long repositoryId, String category) {
        return new IssueQueryService.BacklogQuery(
                null, null, null, null, repositoryId, null, null, null,
                false, false, false, true, null, 1, 0,
                category, null, null, null, null, null, null, null);
    }
}
