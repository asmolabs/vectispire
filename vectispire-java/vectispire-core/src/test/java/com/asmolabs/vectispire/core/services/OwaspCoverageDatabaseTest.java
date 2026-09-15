package com.asmolabs.vectispire.core.services;

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
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * La grille OWASP telle qu'une base la produit.
 *
 * <h2>Ce que ce fichier éprouve, et qui ne pouvait pas l'être avant</h2>
 *
 * <p><b>Sept catégories sur dix étaient annoncées « non couvertes », et deux ne le méritaient
 * pas.</b> Les règles d'analyse de code déclarent leur catégorie OWASP dans leurs propres
 * métadonnées ; ce produit ne lisait pas cette clé, donc aucun constat de code ne pouvait être
 * placé, donc la grille annonçait une absence de couverture qui était une absence de lecture.
 *
 * <p>Les cas ci-dessous portent sur les deux moitiés du chemin : le regroupement en base, qui
 * compte les constats par catégorie sous la visibilité du lecteur, et la lecture des règles
 * installées, qui décide qu'une catégorie <em>sans</em> constat est propre plutôt qu'aveugle.
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
    @DisplayName("place les constats de code dans la catégorie que leur règle a déclarée")
    void codeFindingsLandInTheirDeclaredCategory() {
        installRulesDeclaring("A03");
        sast(alpha, "fp-1", "A03");
        sast(alpha, "fp-2", "A03");
        sast(beta, "fp-3", "A10");

        OwaspCoverage.Grid grid = coverage.grid(Visibility.everything());

        assertThat(line(grid, "A03").state()).isEqualTo(OwaspCoverage.State.FINDINGS);
        assertThat(line(grid, "A03").findings()).isEqualTo(2);

        // A10 n'est déclarée par aucune règle installée ici : les constats existent et la
        // catégorie reste non couverte. C'est voulu — la couverture vient des règles, pas du
        // retard, sans quoi une catégorie sortirait de la grille le jour où on la nettoie.
        assertThat(line(grid, "A10").state()).isEqualTo(OwaspCoverage.State.NOT_COVERED);
        assertThat(line(grid, "A10").findings()).isZero();
    }

    @Test
    @DisplayName("sort A03 de « rien ici ne regarde ça », sans pour autant l'annoncer propre")
    void theBundledRuleOpensTheCategoryWithoutClearingIt() {
        // **Deux phrases différentes, et la nuance est tout l'objet de cette grille.** La règle
        // livrée déclare A03 : la catégorie cesse d'être « aucun scanner ici ne produit ça ».
        // Elle ne devient pas propre pour autant — une seule règle, un seul motif, un seul
        // langage, ce que `RuleCoverage` appelle une instance non configurée. L'annoncer sans
        // constat serait délivrer un certificat de bonne santé sur un examen qui n'a pas eu lieu.
        OwaspCoverage.Grid grid = coverage.grid(Visibility.everything());

        assertThat(line(grid, "A03").state()).isEqualTo(OwaspCoverage.State.NOT_MEASURED);
        assertThat(line(grid, "A03").because())
                .as("la cause la plus fréquente sur une instance neuve doit être nommée")
                .contains("only the rule this product ships is installed");
    }

    @Test
    @DisplayName("ne compte pas un constat de qualité dans une grille de sécurité")
    void qualityFindingsStayOut() {
        // Une règle de qualité peut porter la même métadonnée. La compter placerait dans une
        // grille de sécurité un constat dont ce produit dit par ailleurs qu'il ne fait jamais
        // échouer une barrière.
        installRulesDeclaring("A03");
        IssueEntity quality = issue(alpha, "fp-q", FindingType.QUALITY);
        quality.setOwaspCategory("A03");
        issues.save(quality);

        assertThat(line(coverage.grid(Visibility.everything()), "A03").state())
                .isEqualTo(OwaspCoverage.State.NO_FINDING);
    }

    @Test
    @DisplayName("un constat résolu ne compte plus, et un constat sans catégorie n'entre nulle part")
    void resolvedAndUnplacedFindings() {
        installRulesDeclaring("A03");
        IssueEntity closed = issue(alpha, "fp-closed", FindingType.SAST);
        closed.setOwaspCategory("A03");
        closed.setState(IssueState.RESOLVED.wireName());
        issues.save(closed);

        sast(alpha, "fp-plain", null);

        OwaspCoverage.Grid grid = coverage.grid(Visibility.everything());
        assertThat(line(grid, "A03").state())
                .as("la grille dit ce qui est ouvert, et la plupart des règles ne déclarent rien")
                .isEqualTo(OwaspCoverage.State.NO_FINDING);
    }

    @Test
    @DisplayName("le compte par catégorie porte la visibilité du lecteur")
    void theCountIsScopedToWhatTheReaderMaySee() {
        installRulesDeclaring("A03");
        sast(alpha, "fp-1", "A03");
        sast(beta, "fp-2", "A03");

        // L'inversion que `Visibility` existe pour empêcher, à l'endroit où elle se verrait :
        // une grille qui compterait le parc entier rendrait les constats d'autrui sous le nom du
        // lecteur.
        OwaspCoverage.Grid scoped = coverage.grid(
                Visibility.only(List.of(new ScanTarget.Repository(beta))));

        assertThat(line(scoped, "A03").findings()).isEqualTo(1);
    }

    @Test
    @DisplayName("l'analyse de code éteinte laisse la catégorie non mesurée, constats ou pas")
    void switchedOffIsNotClean() {
        installRulesDeclaring("A03");
        sast(alpha, "fp-1", "A03");
        settings.set(Setting.SAST_ENABLED, "false");

        OwaspCoverage.Grid grid = coverage.grid(Visibility.everything());

        assertThat(line(grid, "A03").state()).isEqualTo(OwaspCoverage.State.NOT_MEASURED);
        assertThat(line(grid, "A03").findings())
                .as("« on a arrêté de regarder » n'est pas « c'est corrigé », et le compte d'hier "
                        + "affiché aujourd'hui se lirait comme une mesure")
                .isZero();
    }

    /**
     * Un jeu de règles téléversé, qui déclare la catégorie voulue.
     *
     * <p>Nécessaire pour que l'analyse de code compte comme atteignant le parc : tant que seules
     * les règles livrées sont là, {@code RuleCoverage} répond « non configurée », et la grille
     * refuse à juste titre de conclure.
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
