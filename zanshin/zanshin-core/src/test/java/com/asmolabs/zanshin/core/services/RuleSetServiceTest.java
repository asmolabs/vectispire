package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.rules.InvalidRuleSetException;
import com.asmolabs.zanshin.common.domain.rules.RuleSet;
import com.asmolabs.zanshin.common.domain.rules.RuleSet.TriageImpact;
import com.asmolabs.zanshin.common.domain.rules.RuleSet.UploadedFile;
import com.asmolabs.zanshin.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.zanshin.core.repositories.Repositories;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

@DisplayName("uploading, costing and activating a rule set")
class RuleSetServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T09:00:00Z");

    private Repositories.RuleSets ruleSets;
    private Repositories.Issues issues;
    private RuleSetService service;

    @BeforeEach
    void wire() {
        ruleSets = mock(Repositories.RuleSets.class);
        issues = mock(Repositories.Issues.class);
        service = new RuleSetService(ruleSets, issues, new ObjectMapper(), Clock.fixed(NOW, ZoneOffset.UTC));

        when(ruleSets.save(any())).thenAnswer(call -> call.getArgument(0));
        when(ruleSets.findByIsActiveTrue()).thenReturn(Optional.empty());
        when(issues.countOpenByIdentifier(anyString(), anyString())).thenReturn(List.of());
    }

    @Test
    @DisplayName("an upload is stored inactive, counted, and hashed")
    void storeDoesNotActivate() {
        SemgrepRuleSetEntity stored = service.store(
                List.of(upload("owasp.yaml", "rules:\n  - id: sql-injection\n"), upload("extra.yml", "rules:\n  - id: xxe\n")),
                "  OWASP  ",
                "alice");

        assertThat(stored.getName()).isEqualTo("OWASP");
        assertThat(stored.getFileCount()).isEqualTo(2);
        assertThat(stored.getRuleCount()).isEqualTo(2);
        assertThat(stored.getUploadedAt()).isEqualTo(NOW);
        assertThat(stored.getContentHash()).isNotBlank();
        // `null`, never `false`: the unique index only counts NULLs as distinct, so `false`
        // would let a second set be stored and the "at most one active" guarantee would be a
        // comment rather than a constraint.
        assertThat(stored.getIsActive()).isNull();
    }

    @Test
    @DisplayName("the stored files round-trip through the JSON column")
    void filesSurviveStorage() {
        SemgrepRuleSetEntity stored = service.store(List.of(upload("owasp.yaml", "rules:\n  - id: sql-injection\n")), "OWASP", null);

        assertThat(service.filesOf(stored))
                .singleElement()
                .returns("owasp.yaml", RuleSet.StoredFile::originalName)
                .returns("rules:\n  - id: sql-injection\n", RuleSet.StoredFile::content);
    }

    @Test
    void refusesAnUnnamedSet() {
        assertThatThrownBy(() -> service.store(List.of(upload("owasp.yaml", "rules:\n  - id: x\n")), "   ", null))
                .isInstanceOf(InvalidRuleSetException.class);
    }

    @Test
    @DisplayName("unreadable stored rules are an error, not a silent fallback")
    void corruptFilesRefuseToBeRead() {
        SemgrepRuleSetEntity row = new SemgrepRuleSetEntity();
        row.setId(7L);
        row.setFiles("{not json");

        // Falling back to the bundled rule here would narrow what every scan looks for while
        // the step still reports as having run.
        assertThatThrownBy(() -> service.filesOf(row)).isInstanceOf(InvalidRuleSetException.class);
    }

    @Test
    @DisplayName("the cost of activating names the rules whose backlog would resolve")
    void impactCountsTheTriageAtRisk() {
        when(ruleSets.findByIsActiveTrue()).thenReturn(Optional.of(set("rules:\n  - id: sql-injection\n  - id: xxe\n")));
        when(issues.countOpenByIdentifier(anyString(), anyString()))
                .thenReturn(List.of(new Object[] {"xxe", 4L}, new Object[] {"sql-injection", 1L}));

        TriageImpact impact = service.impactOf(set("rules:\n  - id: sql-injection\n  - id: ssrf\n"));

        assertThat(impact.losingIssues()).containsExactly("xxe");
        assertThat(impact.affectedIssues()).isEqualTo(4);
        assertThat(impact.addedRules()).isEqualTo(1);
        assertThat(impact.removedRules()).isEqualTo(1);
    }

    @Test
    @DisplayName("a rule that is going away but has no open issue costs nothing")
    void impactIgnoresRulesWithNothingToLose() {
        when(ruleSets.findByIsActiveTrue()).thenReturn(Optional.of(set("rules:\n  - id: xxe\n")));

        TriageImpact impact = service.impactOf(set("rules:\n  - id: ssrf\n"));

        assertThat(impact.losingIssues()).isEmpty();
        assertThat(impact.affectedIssues()).isZero();
        assertThat(impact.removedRules()).isEqualTo(1);
    }

    @Test
    @DisplayName("activation deactivates first, then activates, and re-reads")
    void activationIsOrderedAndRefreshed() {
        SemgrepRuleSetEntity target = set("rules:\n  - id: ssrf\n");
        target.setId(3L);
        SemgrepRuleSetEntity activated = set("rules:\n  - id: ssrf\n");
        activated.setId(3L);
        activated.setIsActive(true);
        // The second read is the one after the two update statements, and it has to see the
        // row as the database now holds it.
        AtomicInteger reads = new AtomicInteger();
        when(ruleSets.findById(3L))
                .thenAnswer(call -> Optional.of(reads.getAndIncrement() == 0 ? target : activated));

        assertThat(service.activate(3L, "approved by security").getIsActive()).isTrue();

        // The order is the guarantee: activating first would collide with the unique index,
        // and the retry would leave no set active at all — the bundled rule, silently.
        InOrder order = inOrder(ruleSets);
        order.verify(ruleSets).deactivateAll();
        order.verify(ruleSets).activate(3L, "approved by security");
    }

    @Test
    void refusesToActivateWhatIsNotThere() {
        when(ruleSets.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.activate(99L, null)).isInstanceOf(InvalidRuleSetException.class);
    }

    /**
     * A stored set, built without going through the service.
     *
     * <p>Calling {@code store} here would invoke a mock inside a {@code when(...)} argument,
     * which Mockito reads as an unfinished stubbing — a confusing failure a long way from its
     * cause.
     */
    private SemgrepRuleSetEntity set(String content) {
        SemgrepRuleSetEntity row = new SemgrepRuleSetEntity();
        try {
            row.setFiles(new ObjectMapper().writeValueAsString(RuleSet.accept(List.of(upload("rules.yaml", content)))));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        return row;
    }

    private static UploadedFile upload(String name, String content) {
        return new UploadedFile(name, content);
    }
}
