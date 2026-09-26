package com.asmolabs.vectispire.core.rules.internal;

import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.core.rules.RuleSetService;
import com.asmolabs.vectispire.core.rules.persistence.SemgrepRuleSetEntity;
import com.asmolabs.vectispire.core.scanning.ScanRuleSets;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/** {@code scanning}'s {@link ScanRuleSets}, answered by this module's rule set store. */
@Component
public class RuleSetsForScans implements ScanRuleSets {

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
}
