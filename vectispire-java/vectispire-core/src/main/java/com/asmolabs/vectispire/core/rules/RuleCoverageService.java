package com.asmolabs.vectispire.core.rules;

import com.asmolabs.vectispire.common.domain.owasp.OwaspTag;
import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.common.scanning.BundledRules;
import com.asmolabs.vectispire.core.repositories.Components;
import com.asmolabs.vectispire.core.rules.persistence.SemgrepRuleSetEntity;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
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
     * A stored file's path, expressed the way the shipped rule tree spells it.
     *
     * <p>The storage name is flat by construction; the original name carries the upstream path. It
     * is the latter that states the language, and prefixing it with {@code semgrep/} puts it in
     * the form {@link RuleCoverage} reads.
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
        // **The original name, not the storage name — without which this evaluation can only
        // answer "not configured".** Uploaded files are stored flat as `rule-0001.yaml`;
        // `RuleCoverage` reads the language from the *path*, and a path with no directory carries
        // none. An operator could therefore import the whole upstream catalogue and go on reading
        // "only the shipped rules are installed", indefinitely.
        //
        // The original name is the upstream path — `java/xss/….yaml`, kept deliberately because it
        // goes into the rule identifier — and it reads like the shipped tree as soon as it is
        // prefixed the same way.
        active.ifPresent(row -> ruleSets.filesOf(row).stream()
                .map(RuleCoverageService::asRuleTreePath)
                .forEach(paths::add));

        return RuleCoverage.assess(paths, components.distinctPurls());
    }

    /**
     * The ecosystems no installed rule covers, for each target that has an inventory.
     *
     * <p><b>Per target, because a fleet-wide answer would fail the wrong builds.</b> An estate
     * holding one Go repository among forty Java ones is {@code PARTIAL}; refusing every verdict
     * on that basis would stop the forty that <em>are</em> examined, and the clause would be
     * switched off within the day. The question a gate asks is about the target in front of it.
     *
     * <p>Keyed by {@code kind:id} — the same scope key the policies use — and targets with nothing
     * uncovered are absent rather than present and empty, so a lookup miss and a clean answer are
     * the same thing to a caller.
     */
    @Transactional(readOnly = true)
    public Map<String, List<String>> uncoveredEcosystemsByTarget() {
        List<String> paths = installedRulePaths();

        Map<String, List<String>> purlsByTarget = new LinkedHashMap<>();
        for (Object[] row : components.distinctPurlsByTarget()) {
            Long repoId = (Long) row[0];
            Long containerId = (Long) row[1];
            String purl = (String) row[2];
            String key = repoId != null ? "repository:" + repoId : "container:" + containerId;
            purlsByTarget.computeIfAbsent(key, ignored -> new ArrayList<>()).add(purl);
        }

        Map<String, List<String>> uncovered = new LinkedHashMap<>();
        purlsByTarget.forEach((key, purls) -> {
            Set<String> gaps = RuleCoverage.assess(paths, purls).uncovered();
            if (!gaps.isEmpty()) {
                uncovered.put(key, List.copyOf(gaps));
            }
        });
        return uncovered;
    }

    /** The rule files this instance scans with: the active set, plus what the jar ships. */
    private List<String> installedRulePaths() {
        List<String> paths = new ArrayList<>(BundledRules.expected());
        ruleSets.active().ifPresent(row -> ruleSets.filesOf(row).stream()
                .map(RuleCoverageService::asRuleTreePath)
                .forEach(paths::add));
        return paths;
    }
}
