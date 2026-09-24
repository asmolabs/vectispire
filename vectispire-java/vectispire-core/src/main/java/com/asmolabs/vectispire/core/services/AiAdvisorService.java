package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.aireview.AiVulnerabilityAdvice;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * The advisor's explanations, restricted to the issues the caller may see.
 *
 * <p><b>An explanation is the finding itself, in prose</b> — the package, the file, the fix. So
 * each lookup here takes the caller's visibility and applies it before anything is read from the
 * row, and {@link AiReviewService} only ever receives an issue somebody was allowed to open.
 */
@Service
public class AiAdvisorService {

    private final AiReviewService reviews;
    private final Issues issues;

    public AiAdvisorService(AiReviewService reviews, Issues issues) {
        this.reviews = reviews;
        this.issues = issues;
    }

    /**
     * @throws java.util.NoSuchElementException for a hidden or absent issue, in the same words.
     *     <b>An absent row goes to the same guard as a hidden one.</b> It had its own 404, worded
     *     "Issue not found: 42" against the guard's "Issue not found.", so the message alone told a
     *     restricted reader which sequential ids existed
     */
    public AiVulnerabilityAdvice explainIssue(long issueId, Visibility allowed) {
        IssueEntity issue = RowVisibility.requireVisible(issues.findById(issueId).orElse(null), allowed);
        return reviews.explainVulnerability(issue);
    }

    /**
     * Explains a CVE from the first visible issue that carries it, or from what the caller passed
     * when none does.
     *
     * <p><b>Narrowed before anything is read</b>, so that a CVE present only in a target the caller
     * was not given gets exactly the answer a CVE present nowhere gets. The route took the first
     * match from anywhere in the estate, and its answer differed depending on whether a match
     * existed — which told a reader with one repository whether a CVE was present in repositories
     * they were never given.
     */
    public AiVulnerabilityAdvice explainCve(
            String cveId,
            String packageName,
            String currentVersion,
            String fixVersion,
            String reachability,
            Visibility allowed) {

        List<IssueEntity> matched = issues.findByIdentifier(cveId).stream()
                .filter(issue -> RowVisibility.isVisible(issue, allowed))
                .toList();
        if (!matched.isEmpty()) {
            return reviews.explainVulnerability(matched.get(0));
        }

        return AiVulnerabilityAdvice.generateDeterministic(
                cveId,
                packageName,
                currentVersion,
                fixVersion,
                reachability != null ? reachability : "UNKNOWN",
                cveId.toUpperCase().contains("2021-44228") || cveId.toUpperCase().contains("2024-3094"),
                0.75);
    }
}
