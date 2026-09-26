package com.asmolabs.vectispire.core.services.issues;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.scanning.ScanIngestor;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The backlog as the ingestion reaches it: the sync's answer handed back, and the delta announced
 * through the pre-commit hook. The last case was {@code ScanIngestorTest}'s while the ingestion called
 * the sync and held the notification sink itself (decision 0029).
 */
@DisplayName("the backlog, as a scan's ingestion reaches it")
class IssueBacklogTest {

    private static final ScanTarget REPOSITORY = new ScanTarget.Repository(3L);

    private IssueSyncService sync;

    @BeforeEach
    void wire() {
        sync = mock(IssueSyncService.class);
    }

    @Test
    @DisplayName("hands back what the sync did, the issue of each finding included")
    void answersTheSync() {
        when(sync.sync(anyLong(), any(), any(), any(), any(), any()))
                .thenReturn(new IssueSyncService.SyncResult(1, 2, 3, 4, List.of(), List.of(), List.of(40L, 41L)));

        ScanIngestor.Reconciliation result = new IssueBacklog(sync, Optional.empty()).reconcile(observation());

        assertThat(result).isEqualTo(new ScanIngestor.Reconciliation(1, 2, 3, 4, List.of(40L, 41L)));
    }

    @Test
    @DisplayName("the delta is queued through the pre-commit hook, not after the sync")
    void notifiesInsideTheTransaction() {
        // A notification written one line later is lost by the very crash the outbox covers.
        IssueEntity opened = new IssueEntity();
        opened.setId(40L);
        opened.setIdentifier("CVE-2021-44228");
        when(sync.sync(anyLong(), any(), any(), any(), any(), any())).thenAnswer(call -> {
            Consumer<IssueSyncService.SyncResult> hook = call.getArgument(5);
            IssueSyncService.SyncResult result =
                    new IssueSyncService.SyncResult(1, 0, 0, 0, List.of(opened), List.of(), List.of(40L));
            hook.accept(result);
            return result;
        });
        AtomicReference<ScanDelta> announced = new AtomicReference<>();

        new IssueBacklog(sync, Optional.of(announced::set)).reconcile(observation());

        assertThat(announced.get()).isNotNull();
        assertThat(announced.get().scanId()).isEqualTo(7L);
        assertThat(announced.get().target()).isEqualTo(REPOSITORY);
        assertThat(announced.get().newIssues()).singleElement()
                .satisfies(issue -> assertThat(issue.identifier()).isEqualTo("CVE-2021-44228"));
    }

    private static ScanIngestor.Observation observation() {
        return new ScanIngestor.Observation(7L, REPOSITORY, List.of(), Set.of(FindingType.SECRET), Map.of());
    }
}
