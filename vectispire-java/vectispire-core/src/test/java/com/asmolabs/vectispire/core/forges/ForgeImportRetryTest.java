package com.asmolabs.vectispire.core.forges;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportRequest;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner.Plan;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner.PlannedSolution;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner.Source;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService.SolutionView;
import com.asmolabs.vectispire.core.targets.TargetImports;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * An import that failed is planned again from what is committed (decision 0037 §5): run again when that plan creates
 * less — something got there first — and thrown as it came when it creates the same, which no race explains. The race
 * itself, on the engines, is {@code ForgeImportIntegrationTest}'s; this pins the decision taken after it.
 */
@DisplayName("an import that lost a race")
class ForgeImportRetryTest {

    private static final Instant AT = Instant.parse("2026-10-03T10:00:00Z");
    private static final UUID CONNECTION = UUID.randomUUID();
    private static final RequestActor ACTOR = new RequestActor("ada", null, null);
    private static final ForgeImportRequest REQUEST =
            new ForgeImportRequest(1L, List.of("1"), null, null, null, null, null);

    private final ImportPlanner planner = mock(ImportPlanner.class);
    private final TargetImports targets = mock(TargetImports.class);
    private final TargetImports.Batch batch = mock(TargetImports.Batch.class);
    private final AuditLogService audit = mock(AuditLogService.class);
    private final ForgeImportService service =
            new ForgeImportService(planner, targets, mock(ForgeImportLinkRepository.class), audit);
    private Source source;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void wired() {
        ForgeConnectionEntity connection = new ForgeConnectionEntity();
        connection.setId(CONNECTION);
        connection.setName("GitLab");
        connection.setKind("gitlab");
        ForgeDiscoveryEntity discovery = new ForgeDiscoveryEntity();
        discovery.setId(1L);
        source = new Source(connection, discovery, ForgeKind.GITLAB);
        when(planner.source(CONNECTION, 1L)).thenReturn(source);
        when(targets.inOneTransaction(eq(ACTOR), any())).thenAnswer(call ->
                ((Function<TargetImports.Batch, Object>) call.getArgument(1)).apply(batch));
    }

    /** A plan filing into solution {@code acme}, to create or already there. */
    private Plan plan(boolean solutionExists) {
        Optional<SolutionView> existing = solutionExists ? Optional.of(new SolutionView(7L, "acme", null, AT)) : Optional.empty();
        return new Plan(source, AT, List.of(), List.of(), List.of(), List.of(new PlannedSolution("acme", existing)),
                List.of(), List.of(), Optional.empty(), Duration.ofDays(7), VisibilityMode.EVERYONE);
    }

    @Test
    @DisplayName("what is committed now creates less: something got there first, and the import runs again")
    void retriedWhenRaced() {
        DataIntegrityViolationException taken = new DataIntegrityViolationException("uq_solution_name");
        when(planner.plan(source, REQUEST)).thenReturn(plan(false), plan(true), plan(true));
        when(batch.solution("acme")).thenThrow(taken)
                .thenReturn(new TargetImports.Placed<>(new SolutionView(7L, "acme", null, AT), false));

        ForgeImports.ForgeImportResult result = service.apply(CONNECTION, REQUEST, ACTOR);

        assertThat(result.solutionsCreated()).isEmpty();
        verify(targets, times(2)).inOneTransaction(eq(ACTOR), any());
        verify(audit, times(1)).record(any());
    }

    @Test
    @DisplayName("what is committed now creates the same: the failure was the import's own, thrown once, as it came")
    void thrownWhenNotRaced() {
        DataIntegrityViolationException broken = new DataIntegrityViolationException("something else");
        when(planner.plan(source, REQUEST)).thenReturn(plan(false));
        when(batch.solution("acme")).thenThrow(broken);

        assertThatThrownBy(() -> service.apply(CONNECTION, REQUEST, ACTOR)).isSameAs(broken);
        verify(targets, times(1)).inOneTransaction(eq(ACTOR), any());
        verify(audit, times(0)).record(any());
    }

    @Test
    @DisplayName("three attempts at most, however the races go")
    void bounded() {
        DataIntegrityViolationException taken = new DataIntegrityViolationException("uq_solution_name");
        when(planner.plan(source, REQUEST)).thenReturn(plan(false), plan(true), plan(true), plan(false), plan(false),
                plan(true));
        when(batch.solution("acme")).thenThrow(taken);
        when(batch.project(anyLong(), any())).thenThrow(taken);

        assertThatThrownBy(() -> service.apply(CONNECTION, REQUEST, ACTOR)).isSameAs(taken);
        verify(targets, times(ForgeImportService.ATTEMPTS)).inOneTransaction(eq(ACTOR), any());
    }
}
