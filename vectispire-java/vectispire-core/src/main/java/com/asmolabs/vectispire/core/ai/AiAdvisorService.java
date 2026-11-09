package com.asmolabs.vectispire.core.ai;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.aireview.AdviceLanguage;
import com.asmolabs.vectispire.common.domain.aireview.AiVulnerabilityAdvice;
import com.asmolabs.vectispire.common.domain.threatintel.Exploitation;
import com.asmolabs.vectispire.common.domain.threatintel.KevListing;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.threatintel.ThreatIntelFeedService;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * The advisor's explanations, restricted to the issues the caller may see.
 *
 * <p><b>An explanation is the finding itself, in prose</b> — the package, the file, the fix. So
 * each lookup here takes the caller's visibility and applies it before anything is read from the
 * row, and {@link AiReviewService} only ever receives an issue somebody was allowed to open.
 *
 * <p><b>Exploitation is read from the stored feeds, and unknown is said.</b> The answer for a CVE
 * the estate does not carry was built on inputs made up here: actively exploited when the
 * identifier contained {@code 2021-44228} or {@code 2024-3094}, and an EPSS probability of 0.75
 * whatever the CVE — both shown on screen as if measured. The KEV catalogue and the EPSS file are
 * synchronised and stored ({@link ThreatIntelFeedService}); the advice says what they hold, or that
 * nothing answered.
 */
@Service
public class AiAdvisorService {

    private final AiReviewService reviews;
    private final IssueCatalog issues;
    private final ThreatIntelFeedService feeds;

    public AiAdvisorService(AiReviewService reviews, IssueCatalog issues, ThreatIntelFeedService feeds) {
        this.reviews = reviews;
        this.issues = issues;
        this.feeds = feeds;
    }

    /**
     * @param language the reader's, as the screen names it ({@link AdviceLanguage#parse}); English
     *     when none is given
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException for a hidden or absent issue, in the same words.
     *     <b>An absent row goes to the same guard as a hidden one.</b> It had its own 404, worded
     *     "Issue not found: 42" against the guard's "Issue not found.", so the message alone told a
     *     restricted reader which sequential ids existed
     */
    public AiVulnerabilityAdvice explainIssue(long issueId, String language, Visibility allowed) {
        AdviceLanguage asked = AdviceLanguage.parse(language);
        IssueView issue = RowVisibility.requireVisibleIssue(issues.issue(issueId).orElse(null), AiAdvisorService::targetOf, allowed);
        return reviews.explainVulnerability(issue, exploitationOf(issue), asked);
    }

    /**
     * Explains a CVE from the first visible issue that carries it, or from the stored feeds alone
     * when none does.
     *
     * <p><b>No component from the caller.</b> The route took a package, a version and a fixed version
     * as parameters and printed them as the advice's facts — "reported in component X, version Y",
     * an upgrade command built from them — on nobody's word but the caller's. Neither screen sent
     * them; an identifier no visible issue carries is explained by what the feeds hold.
     *
     * <p><b>Narrowed before anything is read</b>, so that a CVE present only in a target the caller
     * was not given gets exactly the answer a CVE present nowhere gets. The route took the first
     * match from anywhere in the estate, and its answer differed depending on whether a match
     * existed — which told a reader with one repository whether a CVE was present in repositories
     * they were never given. The feeds are public catalogues, read whole: what they answer does not
     * depend on the estate either.
     */
    public AiVulnerabilityAdvice explainCve(String cveId, String language, Visibility allowed) {
        AdviceLanguage asked = AdviceLanguage.parse(language);

        List<IssueView> matched = issues.withIdentifier(cveId).stream()
                .filter(issue -> allowed.permits(targetOf(issue)))
                .toList();
        if (!matched.isEmpty()) {
            IssueView issue = matched.get(0);
            return reviews.explainVulnerability(issue, exploitationOf(issue), asked);
        }

        return AiVulnerabilityAdvice.forIdentifierAlone(cveId, feeds.exploitationOf(cveId));
    }

    /**
     * The issue's own figures where it holds them, the feeds' for what it cannot tell.
     *
     * <p>A flag the row carries is the catalogue's word at the last re-evaluation, and a score the
     * EPSS file's; they are what every other screen shows for this issue, so they win. What the row
     * cannot say is the difference between "not listed" and "nobody looked" — its {@code isKev} is
     * false either way — nor a score it was never given; the feeds answer those.
     */
    private Exploitation exploitationOf(IssueView issue) {
        if (issue.isKev() && issue.epssScore() != null) {
            return new Exploitation(KevListing.LISTED, issue.epssScore());
        }
        Exploitation stored = feeds.exploitationOf(issue.identifier());
        return new Exploitation(
                issue.isKev() ? KevListing.LISTED : stored.kev(),
                issue.epssScore() != null ? issue.epssScore() : stored.epssScore());
    }

    /** A row attached to neither target is left to {@code Visibility.permits}, as the entity's reading is. */
    private static com.asmolabs.vectispire.common.domain.targets.ScanTarget targetOf(IssueView issue) {
        if (issue.repoId() != null) {
            return new com.asmolabs.vectispire.common.domain.targets.ScanTarget.Repository(issue.repoId());
        }
        return issue.containerId() == null
                ? null
                : new com.asmolabs.vectispire.common.domain.targets.ScanTarget.Container(issue.containerId());
    }
}
