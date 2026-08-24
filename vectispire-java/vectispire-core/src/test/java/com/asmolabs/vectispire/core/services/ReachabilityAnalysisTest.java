package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.reachability.ReachabilityStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ReachabilityAnalyzer cross-correlations")
class ReachabilityAnalysisTest {

    private final ReachabilityAnalyzer analyzer = new ReachabilityAnalyzer();

    @Test
    @DisplayName("marks vulnerable dependency as REACHABLE when SAST finds matching code invocations")
    void detectsReachableVulnerability() {
        FindingEntity scaFinding = new FindingEntity();
        scaFinding.setPackageName("commons-text");
        scaFinding.setSource("trivy");

        FindingEntity sastFinding = new FindingEntity();
        sastFinding.setSource("semgrep");
        sastFinding.setFilePath("src/main/java/com/corp/TemplateHelper.java");
        sastFinding.setLine(42);
        sastFinding.setDescription("Detected call to org.apache.commons.text.StringSubstitutor");

        analyzer.analyzeAndEnrich(scaFinding, List.of(scaFinding, sastFinding));

        assertThat(scaFinding.getReachability()).isEqualTo("REACHABLE");
        assertThat(scaFinding.getReachableSymbols()).contains("TemplateHelper.java:42");

        IssueEntity issue = new IssueEntity();
        analyzer.enrichIssue(issue, List.of(scaFinding));
        assertThat(issue.getReachability()).isEqualTo("REACHABLE");
        assertThat(issue.getReachableSymbols()).contains("TemplateHelper.java:42");
    }

    @Test
    @DisplayName("marks vulnerable dependency as UNREACHABLE when SAST ran but found no calls")
    void detectsUnreachableVulnerability() {
        FindingEntity scaFinding = new FindingEntity();
        scaFinding.setPackageName("log4j-core");
        scaFinding.setSource("trivy");

        FindingEntity sastFinding = new FindingEntity();
        sastFinding.setSource("semgrep");
        sastFinding.setFilePath("src/main/java/com/corp/UnrelatedService.java");
        sastFinding.setDescription("Generic null check");

        analyzer.analyzeAndEnrich(scaFinding, List.of(scaFinding, sastFinding));

        assertThat(scaFinding.getReachability()).isEqualTo("UNREACHABLE");
        assertThat(scaFinding.getReachableSymbols()).isNull();

        IssueEntity issue = new IssueEntity();
        analyzer.enrichIssue(issue, List.of(scaFinding));
        assertThat(issue.getReachability()).isEqualTo("UNREACHABLE");
    }
}
