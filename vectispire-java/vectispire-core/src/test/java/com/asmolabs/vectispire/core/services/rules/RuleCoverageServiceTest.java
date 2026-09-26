package com.asmolabs.vectispire.core.services.rules;

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
 * What the instance knows how to look at, going by what it has installed.
 *
 * <h2>The defect the first case closes</h2>
 *
 * <p><b>This evaluation could only ever answer "not configured", whatever an operator
 * installed.</b> Uploaded files are stored flat — {@code rule-0001.yaml} — and
 * {@link RuleCoverage} reads the language from the <em>path</em>: a path with no directory carries
 * none, so the only language ever seen was the shipped rule's, so the state stayed "only the
 * shipped rules are here". An operator could import the whole upstream catalogue and go on reading
 * the same warning indefinitely.
 *
 * <p>The original name, by contrast, carries the upstream path — kept deliberately because it goes
 * into the rule identifier, and therefore into a finding's fingerprint. That is the one to read.
 */
@DisplayName("rule coverage")
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
    @DisplayName("sees an installed set's language, which flat storage hid")
    void anInstalledSetIsSeen() {
        assertThat(service.assess().state())
                .as("nothing installed: the warning must indeed fire")
                .isEqualTo(RuleCoverage.State.UNCONFIGURED);

        install(new RuleSet.StoredFile("rule-0001.yaml", "java/xss/reflected.yaml", "rules: []"));

        assertThat(service.assess().state())
                .as("an operator installing the upstream catalogue must stop reading \"not configured\"")
                .isNotEqualTo(RuleCoverage.State.UNCONFIGURED);
        assertThat(service.assess().languagesWithRules()).contains("java");
    }

    @Test
    @DisplayName("does not manufacture a language from a file with no directory")
    void aFlatNameDeclaresNoLanguage() {
        // An operator uploading a single file by hand announces no language, and inventing
        // "injection.yaml" as one would silence the warning for nothing.
        install(new RuleSet.StoredFile("rule-0001.yaml", "injection.yaml", "rules: []"));

        assertThat(service.assess().state()).isEqualTo(RuleCoverage.State.UNCONFIGURED);
    }

    @Test
    @DisplayName("reads the OWASP categories the installed rules declare, shipped ones included")
    void declaredCategories() {
        // The shipped rule declares A03: a fresh instance already covers injection.
        assertThat(service.declaredOwaspCategories()).containsExactly("A03");

        install(new RuleSet.StoredFile("rule-0001.yaml", "java/ssrf.yaml", """
                rules:
                  - id: team.ssrf
                    metadata:
                      owasp:
                        - A10:2021 - Server-Side Request Forgery
                """));

        assertThat(service.declaredOwaspCategories())
                .as("the shipped rule's and the installed set's, together")
                .containsExactlyInAnyOrder("A03", "A10");
    }

    private void install(RuleSet.StoredFile... files) {
        SemgrepRuleSetEntity row = new SemgrepRuleSetEntity();
        when(ruleSets.active()).thenReturn(Optional.of(row));
        when(ruleSets.filesOf(any())).thenReturn(List.of(files));
    }
}
