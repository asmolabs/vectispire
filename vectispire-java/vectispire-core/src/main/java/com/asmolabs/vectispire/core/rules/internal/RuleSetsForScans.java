package com.asmolabs.vectispire.core.rules.internal;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.common.scanning.BundledRules;
import java.util.Collections;
import java.util.EnumSet;
import com.asmolabs.vectispire.core.rules.RuleSetService;
import com.asmolabs.vectispire.core.rules.persistence.SemgrepRuleSetEntity;
import com.asmolabs.vectispire.core.scanning.ScanRuleSets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/** {@code scanning}'s {@link ScanRuleSets}, answered by this module's rule set store. */
@Component
public class RuleSetsForScans implements ScanRuleSets {

    /**
     * A set's languages by its content hash. Asked at every task built, and answering means decoding
     * every file of the set — up to {@code RuleSet.MAX_TOTAL_BYTES} — so it is kept: a hash names one
     * content forever, and the answer cannot go stale. Bounded, since sets come and go.
     */
    private static final int REMEMBERED = 16;

    private final Map<String, Set<Language>> read = new ConcurrentHashMap<>();

    private final RuleSetService ruleSets;

    public RuleSetsForScans(RuleSetService ruleSets) {
        this.ruleSets = ruleSets;
    }

    @Override
    public Optional<String> activeHash() {
        return ruleSets.active().map(SemgrepRuleSetEntity::getContentHash);
    }

    @Override
    public List<RuleSet.StoredFile> filesOf(String contentHash) {
        return ruleSets.byHash(contentHash).map(ruleSets::filesOf).orElse(List.of());
    }

    @Override
    public Set<Language> languagesRead(String contentHash) {
        // The bundled rules are placed on every scan, a set or not (`RulePlacement.placeBundled`).
        Set<Language> bundled = RuleCoverage.languagesRead(BundledRules.expected());
        if (contentHash == null) {
            return bundled;
        }
        Set<Language> cached = read.get(contentHash);
        if (cached == null) {
            List<RuleSet.StoredFile> files = filesOf(contentHash);
            cached = RuleCoverage.languagesRead(files.stream().map(RuleCoverage::ruleTreePath).toList());
            if (files.isEmpty()) {
                // No set has the hash (yet, or any more): not remembered, since a set stored later under
                // it would otherwise read as reading nothing.
                return bundled;
            }
            if (read.size() >= REMEMBERED) {
                read.clear();
            }
            read.put(contentHash, cached);
        }
        Set<Language> all = EnumSet.noneOf(Language.class);
        all.addAll(bundled);
        all.addAll(cached);
        return Collections.unmodifiableSet(all);
    }
}
