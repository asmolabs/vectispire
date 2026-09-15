package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.common.domain.owasp.OwaspTag;
import com.asmolabs.vectispire.common.scanning.BundledRules;
import com.asmolabs.vectispire.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.vectispire.core.repositories.Components;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * What this instance can see, assembled from what it has installed and what it has inventoried.
 *
 * <p>The two halves come from different places and neither is expensive: the rule paths from the
 * active rule set plus the files the jar ships, and the ecosystems from the distinct package URLs
 * the component inventory already holds.
 *
 * <p><b>The bundled files are counted even though nobody installed them</b>, because they are
 * what a fresh instance actually scans with — pretending an untouched deployment has no rules at
 * all would be a different lie from the one being corrected.
 */
@Service
public class RuleCoverageService {

    private final RuleSetService ruleSets;
    private final Components components;

    public RuleCoverageService(RuleSetService ruleSets, Components components) {
        this.ruleSets = ruleSets;
        this.components = components;
    }

    /**
     * Le chemin d'un fichier stocké, exprimé comme l'arbre des règles livrées l'épelle.
     *
     * <p>Le nom de stockage est plat par construction ; le nom d'origine porte le chemin amont.
     * C'est ce dernier qui dit le langage, et le préfixer de {@code semgrep/} le met dans la
     * forme que {@link RuleCoverage} lit.
     */
    private static String asRuleTreePath(RuleSet.StoredFile file) {
        String origin = file.originalName() == null ? "" : file.originalName().replace('\\', '/');
        return origin.contains("/") ? "semgrep/" + origin : file.path();
    }

    /**
     * The OWASP categories the installed rules declare about themselves.
     *
     * <p><b>Read from the rules, not from the findings.</b> Deriving the set from the categories
     * that already carry a finding would make "nothing found here" indistinguishable from "no
     * rule looks here" — and would flip a category out of the grid on the day its last finding
     * is fixed, which is the moment it most deserves to say "looked at, clean".
     *
     * <p>The bundled files are read alongside the active set, for the reason {@link #assess()}
     * gives: they are what a fresh instance actually scans with.
     */

    @Transactional(readOnly = true)
    public Set<String> declaredOwaspCategories() {
        Set<String> declared = new LinkedHashSet<>();
        BundledRules.expected().stream()
                .filter(path -> path.startsWith("semgrep/"))
                .forEach(path -> declared.addAll(OwaspTag.declaredIn(BundledRules.contentOf(path))));

        ruleSets.active().ifPresent(row -> ruleSets.filesOf(row)
                .forEach(file -> declared.addAll(OwaspTag.declaredIn(file.content()))));

        return declared;
    }

    @Transactional(readOnly = true)
    public RuleCoverage.Assessment assess() {
        List<String> paths = new ArrayList<>(BundledRules.expected());

        Optional<SemgrepRuleSetEntity> active = ruleSets.active();
        // **Le nom d'origine, et non le nom de stockage — sans quoi cette évaluation ne peut
        // répondre que « non configurée ».** Les fichiers téléversés sont rangés à plat sous
        // `rule-0001.yaml` ; `RuleCoverage` lit le langage dans le *chemin*, et un chemin sans
        // dossier n'en porte aucun. Un opérateur pouvait donc importer tout le catalogue amont et
        // continuer à lire « seules les règles livrées sont installées », indéfiniment.
        //
        // Le nom d'origine est le chemin amont — `java/xss/…​.yaml`, conservé délibérément parce
        // qu'il entre dans l'identifiant de règle — et il se lit comme l'arbre livré dès qu'on le
        // préfixe de la même façon.
        active.ifPresent(row -> ruleSets.filesOf(row).stream()
                .map(RuleCoverageService::asRuleTreePath)
                .forEach(paths::add));

        return RuleCoverage.assess(paths, components.distinctPurls());
    }
}
