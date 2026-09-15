package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.vectispire.core.repositories.Components;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Ce que l'instance sait regarder, d'après ce qu'elle a installé.
 *
 * <h2>Le défaut que le premier cas ferme</h2>
 *
 * <p><b>Cette évaluation ne pouvait répondre que « non configurée », quoi qu'un opérateur
 * installe.</b> Les fichiers téléversés sont rangés à plat — {@code rule-0001.yaml} — et
 * {@link RuleCoverage} lit le langage dans le <em>chemin</em> : un chemin sans dossier n'en porte
 * aucun, donc la seule langue jamais vue était celle de la règle livrée, donc l'état restait
 * « seules les règles livrées sont là ». Un opérateur pouvait importer tout le catalogue amont
 * et lire indéfiniment le même avertissement.
 *
 * <p>Le nom d'origine, lui, porte le chemin amont — conservé délibérément parce qu'il entre dans
 * l'identifiant de règle, donc dans l'empreinte d'un constat. C'est celui-là qu'il fallait lire.
 */
@DisplayName("la couverture des règles")
class RuleCoverageServiceTest {

    private RuleSetService ruleSets;
    private Components components;
    private RuleCoverageService service;

    @BeforeEach
    void wire() {
        ruleSets = mock(RuleSetService.class);
        components = mock(Components.class);
        service = new RuleCoverageService(ruleSets, components);

        when(ruleSets.active()).thenReturn(Optional.empty());
        when(components.distinctPurls()).thenReturn(List.of());
    }

    @Test
    @DisplayName("voit le langage d'un jeu installé, que son rangement à plat masquait")
    void anInstalledSetIsSeen() {
        assertThat(service.assess().state())
                .as("rien d'installé : l'avertissement doit bien se déclencher")
                .isEqualTo(RuleCoverage.State.UNCONFIGURED);

        install(new RuleSet.StoredFile("rule-0001.yaml", "java/xss/reflected.yaml", "rules: []"));

        assertThat(service.assess().state())
                .as("un opérateur qui installe le catalogue amont doit cesser de lire « non configurée »")
                .isNotEqualTo(RuleCoverage.State.UNCONFIGURED);
        assertThat(service.assess().languagesWithRules()).contains("java");
    }

    @Test
    @DisplayName("ne fabrique pas un langage à partir d'un fichier sans dossier")
    void aFlatNameDeclaresNoLanguage() {
        // Un opérateur qui téléverse un seul fichier à la main n'annonce aucun langage, et
        // inventer « injection.yaml » comme langue rendrait l'avertissement muet pour rien.
        install(new RuleSet.StoredFile("rule-0001.yaml", "injection.yaml", "rules: []"));

        assertThat(service.assess().state()).isEqualTo(RuleCoverage.State.UNCONFIGURED);
    }

    @Test
    @DisplayName("lit les catégories OWASP que les règles installées déclarent, livrées comprises")
    void declaredCategories() {
        // La règle livrée déclare A03 : une instance neuve couvre déjà l'injection.
        assertThat(service.declaredOwaspCategories()).containsExactly("A03");

        install(new RuleSet.StoredFile("rule-0001.yaml", "java/ssrf.yaml", """
                rules:
                  - id: team.ssrf
                    metadata:
                      owasp:
                        - A10:2021 - Server-Side Request Forgery
                """));

        assertThat(service.declaredOwaspCategories())
                .as("celles de la règle livrée et celles du jeu installé, ensemble")
                .containsExactlyInAnyOrder("A03", "A10");
    }

    private void install(RuleSet.StoredFile... files) {
        SemgrepRuleSetEntity row = new SemgrepRuleSetEntity();
        when(ruleSets.active()).thenReturn(Optional.of(row));
        when(ruleSets.filesOf(any())).thenReturn(List.of(files));
    }
}
