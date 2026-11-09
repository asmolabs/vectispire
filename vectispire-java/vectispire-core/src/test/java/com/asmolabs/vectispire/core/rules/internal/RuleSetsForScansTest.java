package com.asmolabs.vectispire.core.rules.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.core.rules.RuleSetService;
import com.asmolabs.vectispire.core.rules.persistence.SemgrepRuleSetEntity;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The languages a task's Semgrep rules read, as the scan records them when the task is built — what a
 * checklist compares with the tree's languages (decision 0032 §6).
 */
@DisplayName("the languages a scan's rules read")
class RuleSetsForScansTest {

    private final RuleSetService store = mock(RuleSetService.class);
    private final RuleSetsForScans ruleSets = new RuleSetsForScans(store);

    @Test
    @DisplayName("with no set, the bundled rules alone: Python")
    void bundledOnly() {
        assertThat(ruleSets.languagesRead(null)).containsExactly(Language.PYTHON);
    }

    @Test
    @DisplayName("a set adds its directories to the bundled rules, read once per hash")
    void aSet() {
        SemgrepRuleSetEntity row = new SemgrepRuleSetEntity();
        when(store.byHash("h")).thenReturn(Optional.of(row));
        when(store.filesOf(row)).thenReturn(List.of(
                new RuleSet.StoredFile("rule-0001.yaml", "java/security/xss.yaml", "rules: []"),
                new RuleSet.StoredFile("rule-0002.yaml", "javascript/express/a.yaml", "rules: []")));

        assertThat(ruleSets.languagesRead("h")).containsExactlyInAnyOrder(Language.PYTHON, Language.JAVA, Language.JAVASCRIPT);
        assertThat(ruleSets.languagesRead("h")).containsExactlyInAnyOrder(Language.PYTHON, Language.JAVA, Language.JAVASCRIPT);
        verify(store, times(1)).filesOf(any());
    }

    @Test
    @DisplayName("a hash no set has reads as the bundled rules, and is asked again next time")
    void anUnknownHash() {
        when(store.byHash("gone")).thenReturn(Optional.empty());
        assertThat(ruleSets.languagesRead("gone")).containsExactly(Language.PYTHON);
        ruleSets.languagesRead("gone");
        verify(store, times(2)).byHash("gone");
    }
}
