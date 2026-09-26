package com.asmolabs.vectispire.core.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.rules.RuleSetService;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The OWASP grid as a database produces it.
 *
 * <h2>What this file tests, and what could not be tested before</h2>
 *
 * <p><b>Seven categories out of ten were announced "not covered", and two did not deserve it.</b>
 * Code-analysis rules declare their OWASP category in their own metadata; this product did not read
 * that key, so no code finding could be placed, so the grid announced an absence of coverage that
 * was an absence of reading.
 *
 * <p>The cases below cover both halves of the path: the grouping in the database, which counts
 * findings by category under the reader's visibility, and the reading of the installed rules, which
 * decides that a category <em>without</em> a finding is clean rather than blind.
 */
@DisplayName("la grille OWASP, contre une base")
class OwaspCoverageDatabaseTest extends VectispireContextTest {

    @Autowired
    private OwaspCoverageService coverage;

    @Autowired
    private SettingsService settings;

    @Autowired
    private RuleSetService ruleSets;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private Scans scans;

    private long alpha;
    private long beta;

    @BeforeEach
    void seed() {
        issues.deleteAll();
        scans.deleteAll();
        repositories.deleteAll();

        settings.set(Setting.SAST_ENABLED, "true");
        ruleSets.deactivateAll();

        alpha = repository("ssh://git@example.com/team/alpha.git", "alpha");
        beta = repository("ssh://git@example.com/team/beta.git", "beta");
        scan(alpha);
        scan(beta);
    }

    @Test
    @DisplayName("places code findings in the category their rule declared")
    void codeFindingsLandInTheirDeclaredCategory() {
        installRulesDeclaring("A03");
        sast(alpha, "fp-1", "A03");
        sast(alpha, "fp-2", "A03");
        sast(beta, "fp-3", "A10");

        OwaspCoverage.Grid grid = coverage.grid(Visibility.everything());

        assertThat(line(grid, "A03").state()).isEqualTo(OwaspCoverage.State.FINDINGS);
        assertThat(line(grid, "A03").findings()).isEqualTo(2);

        // A10 is declared by no rule installed here: the findings exist and the category stays
        // uncovered. That is intended — coverage comes from the rules, not from the backlog,
        // without which a category would drop out of the grid the day it is cleaned up.
        assertThat(line(grid, "A10").state()).isEqualTo(OwaspCoverage.State.NOT_COVERED);
        assertThat(line(grid, "A10").findings()).isZero();
    }

    @Test
    @DisplayName("moves A03 out of \"nothing here looks at that\", without calling it clean")
    void theBundledRuleOpensTheCategoryWithoutClearingIt() {
        // **Two different sentences, and the distinction is the whole point of this grid.** The
        // shipped rule declares A03: the category stops being "no scanner here produces that". It
        // does not thereby become clean — one rule, one pattern, one language, what `RuleCoverage`
        // calls an unconfigured instance. Announcing it clean with no finding would be issuing a
        // clean bill of health for an examination that never took place.
        OwaspCoverage.Grid grid = coverage.grid(Visibility.everything());

        assertThat(line(grid, "A03").state()).isEqualTo(OwaspCoverage.State.NOT_MEASURED);
        assertThat(line(grid, "A03").because())
                .as("the commonest cause on a fresh instance must be named")
                .contains("only the rule this product ships is installed");
    }

    @Test
    @DisplayName("does not count a quality finding in a security grid")
    void qualityFindingsStayOut() {
        // A quality rule can carry the same metadata. Counting it would place in a security grid a
        // finding this product elsewhere says never fails a gate.
        installRulesDeclaring("A03");
        IssueEntity quality = issue(alpha, "fp-q", FindingType.QUALITY);
        quality.setOwaspCategory("A03");
        issues.save(quality);

        assertThat(line(coverage.grid(Visibility.everything()), "A03").state())
                .isEqualTo(OwaspCoverage.State.NO_FINDING);
    }

    @Test
    @DisplayName("a resolved finding no longer counts, and one with no category goes nowhere")
    void resolvedAndUnplacedFindings() {
        installRulesDeclaring("A03");
        IssueEntity closed = issue(alpha, "fp-closed", FindingType.SAST);
        closed.setOwaspCategory("A03");
        closed.setState(IssueState.RESOLVED.wireName());
        issues.save(closed);

        sast(alpha, "fp-plain", null);

        OwaspCoverage.Grid grid = coverage.grid(Visibility.everything());
        assertThat(line(grid, "A03").state())
                .as("the grid says what is open, and most rules declare nothing")
                .isEqualTo(OwaspCoverage.State.NO_FINDING);
    }

    @Test
    @DisplayName("the count by category carries the reader's visibility")
    void theCountIsScopedToWhatTheReaderMaySee() {
        installRulesDeclaring("A03");
        sast(alpha, "fp-1", "A03");
        sast(beta, "fp-2", "A03");

        // The inversion `Visibility` exists to prevent, at the place where it would show: a grid
        // counting the whole estate would render other people's findings under the reader's
        // name.
        OwaspCoverage.Grid scoped = coverage.grid(
                Visibility.only(List.of(new ScanTarget.Repository(beta))));

        assertThat(line(scoped, "A03").findings()).isEqualTo(1);
    }

    @Test
    @DisplayName("code analysis switched off leaves the category unmeasured, findings or not")
    void switchedOffIsNotClean() {
        installRulesDeclaring("A03");
        sast(alpha, "fp-1", "A03");
        settings.set(Setting.SAST_ENABLED, "false");

        OwaspCoverage.Grid grid = coverage.grid(Visibility.everything());

        assertThat(line(grid, "A03").state()).isEqualTo(OwaspCoverage.State.NOT_MEASURED);
        assertThat(line(grid, "A03").findings())
                .as("\"we stopped looking\" is not \"it is fixed\", and yesterday's count shown "
                        + "today would read as a measurement")
                .isZero();
    }

    /**
     * An uploaded rule set, declaring the category wanted.
     *
     * <p>Needed for code analysis to count as reaching the estate: as long as only the shipped
     * rules are there, {@code RuleCoverage} answers "not configured", and the grid rightly refuses
     * to conclude.
     */
    private void installRulesDeclaring(String category) {
        String rule = """
                rules:
                  - id: team.injection
                    languages: [java]
                    severity: ERROR
                    metadata:
                      category: security
                      owasp:
                        - %s:2021 - Injection
                    message: an injection
                    patterns:
                      - pattern: exec(...)
                """.formatted(category);

        ruleSets.activate(ruleSets.store(
                List.of(new RuleSet.UploadedFile("java/injection.yaml", rule)), "team rules", "tester").getId(),
                "installed by a test");
    }

    private static OwaspCoverage.CoverageLine line(OwaspCoverage.Grid grid, String id) {
        return grid.lines().stream().filter(line -> line.id().equals(id)).findFirst().orElseThrow();
    }

    private long repository(String url, String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private void scan(long repoId) {
        ScanEntity entity = new ScanEntity();
        entity.setRepoId(repoId);
        entity.setStatus(ScanStatus.COMPLETED.wireName());
        entity.setBranch("main");
        entity.setCreatedAt(Instant.parse("2026-01-01T00:00:00Z"));
        scans.save(entity);
    }

    private void sast(long repoId, String fingerprint, String category) {
        IssueEntity issue = issue(repoId, fingerprint, FindingType.SAST);
        issue.setOwaspCategory(category);
        issues.save(issue);
    }

    private IssueEntity issue(long repoId, String fingerprint, FindingType type) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(fingerprint);
        issue.setType(type.wireName());
        issue.setIdentifier("rule." + fingerprint);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.parse("2026-01-01T00:00:00Z"));
        issue.setLastSeenAt(Instant.parse("2026-01-01T00:00:00Z"));
        issue.setTimesSeen(1);
        return issue;
    }
}
