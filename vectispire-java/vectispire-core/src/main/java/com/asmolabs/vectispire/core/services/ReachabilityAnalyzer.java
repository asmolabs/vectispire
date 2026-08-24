package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.reachability.ReachabilityStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.stereotype.Service;

/**
 * Correlates SCA vulnerabilities with SAST code evidence to determine actual symbol reachability.
 */
@Service
public class ReachabilityAnalyzer {

    private static final Set<String> HIGH_RISK_SYMBOLS = Set.of(
            "StringSubstitutor", "lookup", "deserialize", "parseObject", "eval",
            "exec", "XMLDecoder", "XPathExpression", "readObject", "unmarshall");

    public void analyzeAndEnrich(FindingEntity finding, List<FindingEntity> allScanFindings) {
        if (finding.getPackageName() == null || finding.getPackageName().isBlank()) {
            finding.setReachability(ReachabilityStatus.UNKNOWN.name());
            return;
        }

        String pkg = finding.getPackageName().toLowerCase(Locale.ROOT);
        String pkgDots = pkg.replace('-', '.');
        String pkgUnderscores = pkg.replace('-', '_');

        boolean hasSastFindings = allScanFindings.stream()
                .anyMatch(f -> "semgrep".equalsIgnoreCase(f.getSource()));

        // Check if any SAST rule or finding points directly to this package or its critical symbols
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
        } else if (hasSastFindings) {
            finding.setReachability(ReachabilityStatus.UNREACHABLE.name());
            finding.setReachableSymbols(null);
        } else {
            finding.setReachability(ReachabilityStatus.UNKNOWN.name());
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
            String symbols = relatedFindings.stream()
                    .map(FindingEntity::getReachableSymbols)
                    .filter(s -> s != null && !s.isBlank())
                    .findFirst()
                    .orElse(null);
            issue.setReachableSymbols(symbols);
        } else {
            boolean allUnreachable = relatedFindings.stream()
                    .allMatch(f -> ReachabilityStatus.UNREACHABLE.name().equalsIgnoreCase(f.getReachability()));
            issue.setReachability(allUnreachable ? ReachabilityStatus.UNREACHABLE.name() : ReachabilityStatus.UNKNOWN.name());
        }
    }
}
