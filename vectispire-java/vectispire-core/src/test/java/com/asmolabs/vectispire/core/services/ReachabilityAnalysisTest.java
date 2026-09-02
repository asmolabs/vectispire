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
    @DisplayName("no matching code finding is UNKNOWN, not a clean bill of health")
    void detectsUnreachableVulnerability() {
        FindingEntity scaFinding = new FindingEntity();
        scaFinding.setPackageName("log4j-core");
        scaFinding.setSource("trivy");

        FindingEntity sastFinding = new FindingEntity();
        sastFinding.setSource("semgrep");
        sastFinding.setFilePath("src/main/java/com/corp/UnrelatedService.java");
        sastFinding.setDescription("Generic null check");

        analyzer.analyzeAndEnrich(scaFinding, List.of(scaFinding, sastFinding));

        // **Ce cas exigeait UNREACHABLE, et c'était le cœur du défaut.** L'analyseur ne suit aucun
        // graphe d'appels : il cherche le nom du paquet en sous-chaîne dans les constats Semgrep du
        // scan. Ne rien trouver signifiait « non atteignable », donc `not_affected` dans OpenVEX et
        // `known_not_affected` dans CSAF — l'absence de preuve publiée comme une preuve d'absence,
        // sur un produit dont l'analyse de code est désactivée par défaut et qui ne livre qu'une
        // règle Semgrep. Cet analyseur peut lever la main ; il ne peut disculper personne.
        assertThat(scaFinding.getReachability()).isEqualTo("UNKNOWN");
        assertThat(scaFinding.getReachableSymbols()).isNull();

        IssueEntity issue = new IssueEntity();
        analyzer.enrichIssue(issue, List.of(scaFinding));
        assertThat(issue.getReachability()).isEqualTo("UNKNOWN");
    }
}
