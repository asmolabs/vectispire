package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.reachability.ReachabilityStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Service;

/**
 * Looks for code evidence that a vulnerable package is used, and says so <b>only when it finds
 * some</b>.
 *
 * <p><b>This is a text correlation, not a call graph.</b> A dependency is marked
 * {@link ReachabilityStatus#REACHABLE} when a Semgrep finding from the same scan mentions the
 * package name — in its description or in its file path. That is a useful pointer: it names a file
 * and a line where somebody should look. It is not proof that the vulnerable method is invoked, and
 * nothing here should be worded as though it were.
 *
 * <p><b>What this class no longer does, and why it is the important part.</b> It used to answer
 * {@link ReachabilityStatus#UNREACHABLE} whenever Semgrep had produced any finding at all and none
 * of them mentioned the package. That is the absence of evidence being reported as evidence of
 * absence, and the conditions make it near-certain: source analysis is off by default, the product
 * ships a single Semgrep rule for licensing reasons, and a repository that switches it on without
 * installing rule sets gets a handful of findings against a few hundred dependencies. Nearly every
 * component would have been stamped "not reachable".
 *
 * <p>That stamp was not cosmetic. {@code VexGeneratorService} turned it into an OpenVEX
 * {@code not_affected} carrying the sentence "static analysis verified no direct call path invokes
 * the vulnerable code", and {@code CsafGeneratorService} placed the product in the CSAF
 * {@code known_not_affected} list — machine-readable claims, shipped to customers, with no human
 * in the loop. A claim of that weight cannot rest on a substring search that did not match.
 *
 * <p>So the analyzer is now one-directional: it can raise a hand, it cannot clear anybody.
 * "No evidence found" is {@link ReachabilityStatus#UNKNOWN}, which is what it always meant.
 * Declaring a component unaffected stays available where it belongs — a person triaging the issue,
 * with a justification recorded against their name.
 */
@Service
public class ReachabilityAnalyzer {

    public void analyzeAndEnrich(FindingEntity finding, List<FindingEntity> allScanFindings) {
        if (finding.getPackageName() == null || finding.getPackageName().isBlank()) {
            finding.setReachability(ReachabilityStatus.UNKNOWN.name());
            return;
        }

        String pkg = finding.getPackageName().toLowerCase(Locale.ROOT);
        String pkgDots = pkg.replace('-', '.');
        String pkgUnderscores = pkg.replace('-', '_');

        // The evidence is a place to look: the file and line of a code finding that names this
        // package. Stored under a column called `reachable_symbols`, which it has never contained.
        List<String> matchedEvidence = allScanFindings.stream()
                .filter(f -> "semgrep".equalsIgnoreCase(f.getSource()))
                .filter(f -> {
                    String desc = f.getDescription() != null ? f.getDescription().toLowerCase(Locale.ROOT) : "";
                    String path = f.getFilePath() != null ? f.getFilePath().toLowerCase(Locale.ROOT) : "";
                    return desc.contains(pkg) || desc.contains(pkgDots) || desc.contains(pkgUnderscores)
                            || path.contains(pkg) || path.contains(pkgDots) || path.contains(pkgUnderscores);
                })
                .map(f -> f.getFilePath() + (f.getLine() != null ? ":" + f.getLine() : ""))
                .toList();

        if (!matchedEvidence.isEmpty()) {
            finding.setReachability(ReachabilityStatus.REACHABLE.name());
            finding.setReachableSymbols(String.join(", ", matchedEvidence));
        } else {
            // Not "unreachable". Nothing here looked for a call path, so nothing here can report
            // the absence of one.
            finding.setReachability(ReachabilityStatus.UNKNOWN.name());
            finding.setReachableSymbols(null);
        }
    }

    public void enrichIssue(IssueEntity issue, List<FindingEntity> relatedFindings) {
        if (relatedFindings.isEmpty()) {
            return;
        }
        boolean anyReachable = relatedFindings.stream()
                .anyMatch(f -> ReachabilityStatus.REACHABLE.name().equalsIgnoreCase(f.getReachability()));
        if (anyReachable) {
            issue.setReachability(ReachabilityStatus.REACHABLE.name());
            issue.setReachableSymbols(relatedFindings.stream()
                    .map(FindingEntity::getReachableSymbols)
                    .filter(s -> s != null && !s.isBlank())
                    .findFirst()
                    .orElse(null));
        } else {
            issue.setReachability(ReachabilityStatus.UNKNOWN.name());
        }
    }
}
