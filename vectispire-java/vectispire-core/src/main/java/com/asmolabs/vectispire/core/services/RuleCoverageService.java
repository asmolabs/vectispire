package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.common.scanning.BundledRules;
import com.asmolabs.vectispire.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.vectispire.core.repositories.Components;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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

    @Transactional(readOnly = true)
    public RuleCoverage.Assessment assess() {
        List<String> paths = new ArrayList<>(BundledRules.expected());

        Optional<SemgrepRuleSetEntity> active = ruleSets.active();
        active.ifPresent(row -> ruleSets.filesOf(row).stream().map(RuleSet.StoredFile::path).forEach(paths::add));

        return RuleCoverage.assess(paths, components.distinctPurls());
    }
}
