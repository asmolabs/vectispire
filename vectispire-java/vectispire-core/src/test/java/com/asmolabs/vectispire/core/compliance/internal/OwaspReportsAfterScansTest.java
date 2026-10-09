package com.asmolabs.vectispire.core.compliance.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The writer of the reports completed scans ask for: one at a time, folded per repository, never beside a
 * report already being written, and never stopped by one that failed.
 *
 * <p>The thread is forced into each interleaving with latches rather than left to timing: a lock tested by
 * luck passes with the lock removed.
 */
@DisplayName("the OWASP reports written after scans")
class OwaspReportsAfterScansTest {

    private final OwaspReviewService reviews = mock(OwaspReviewService.class);
    private final TargetCatalog targets = mock(TargetCatalog.class);
    private final SettingsService settings = mock(SettingsService.class);
    private final AuditLogService audit = mock(AuditLogService.class);
    private OwaspReportsAfterScans writer;

    @BeforeEach
    void wire() {
        when(settings.isEnabled(Setting.AI_REVIEW_ENABLED)).thenReturn(true);
        when(settings.isEnabled(Setting.AI_REVIEW_OWASP_AFTER_SCAN)).thenReturn(true);
        when(targets.repository(anyLong())).thenAnswer(call -> Optional.of(repository(call.getArgument(0))));
        when(reviews.runAfterScan(any(), anyLong())).thenAnswer(call -> written());
        writer = new OwaspReportsAfterScans(reviews, targets, settings, audit, Duration.ofMillis(50));
    }

    @AfterEach
    void stop() {
        writer.stop();
    }

    @Test
    @DisplayName("holds nothing while either switch is off")
    void offHoldsNothing() {
        when(settings.isEnabled(Setting.AI_REVIEW_ENABLED)).thenReturn(false);

        assertThat(writer.offer(1, 10)).isEqualTo(OwaspReportsAfterScans.Offer.SWITCHED_OFF);

        verify(reviews, after(200).never()).runAfterScan(any(), anyLong());
    }

    @Test
    @DisplayName("ten scans of a repository waiting their turn are one report, from the newest")
    void aBurstIsFolded() throws Exception {
        CountDownLatch writing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(reviews.runAfterScan(argThat(repository -> repository != null && repository.id() == 1), anyLong()))
                .thenAnswer(call -> {
                    writing.countDown();
                    release.await(10, TimeUnit.SECONDS);
                    return written();
                });

        assertThat(writer.offer(1, 1)).isEqualTo(OwaspReportsAfterScans.Offer.HELD);
        assertThat(writing.await(5, TimeUnit.SECONDS)).isTrue();

        assertThat(writer.offer(2, 10)).isEqualTo(OwaspReportsAfterScans.Offer.HELD);
        assertThat(writer.offer(2, 12)).isEqualTo(OwaspReportsAfterScans.Offer.FOLDED);
        // A delivery arriving late names an older scan: the held request keeps the newest.
        assertThat(writer.offer(2, 11)).isEqualTo(OwaspReportsAfterScans.Offer.FOLDED);
        // The repository being written now is not asked again.
        assertThat(writer.offer(1, 2)).isEqualTo(OwaspReportsAfterScans.Offer.ALREADY_RUNNING);
        // One at a time: nothing of repository 2 starts while repository 1 is being written.
        verify(reviews, after(200).never()).runAfterScan(argThat(repository -> repository.id() == 2), anyLong());

        release.countDown();

        verify(reviews, timeout(5000)).runAfterScan(argThat(repository -> repository.id() == 2), eq(12L));
        verify(reviews, after(200).never()).runAfterScan(argThat(repository -> repository.id() == 2), eq(10L));
        verify(reviews, never()).runAfterScan(argThat(repository -> repository.id() == 2), eq(11L));
        verify(reviews, never()).runAfterScan(argThat(repository -> repository.id() == 1), eq(2L));
    }

    @Test
    @DisplayName("a repository whose report is running elsewhere is not asked again")
    void runningElsewhereIsSkipped() {
        when(reviews.isRunning(3)).thenReturn(true);

        assertThat(writer.offer(3, 30)).isEqualTo(OwaspReportsAfterScans.Offer.ALREADY_RUNNING);

        verify(reviews, after(200).never()).runAfterScan(any(), anyLong());
    }

    @Test
    @DisplayName("waits while any report is being written anywhere, then writes")
    void waitsForTheModel() {
        when(reviews.anyRunning()).thenReturn(true, true, false);

        assertThat(writer.offer(4, 40)).isEqualTo(OwaspReportsAfterScans.Offer.HELD);

        verify(reviews, timeout(5000)).runAfterScan(argThat(repository -> repository.id() == 4), eq(40L));
        verify(reviews, timeout(5000).times(3)).anyRunning();
    }

    @Test
    @DisplayName("a report that failed stops neither the thread nor the next report, and is not audited as written")
    void aFailureIsSurvived() {
        when(reviews.runAfterScan(argThat(repository -> repository != null && repository.id() == 5), anyLong()))
                .thenThrow(new OwaspReviewService.ReviewRefusedException("Scan 50 of this repository no longer exists."));

        writer.offer(5, 50);
        verify(reviews, timeout(5000)).runAfterScan(argThat(repository -> repository.id() == 5), eq(50L));
        writer.offer(6, 60);

        verify(reviews, timeout(5000)).runAfterScan(argThat(repository -> repository.id() == 6), eq(60L));
        verify(audit, timeout(5000)).record(argThat(entry -> entry.resourceId().equals("6") && entry.userId() == null));
        verify(audit, never()).record(argThat(entry -> entry.resourceId().equals("5")));
    }

    private static RepositoryView repository(long id) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setId(id);
        entity.setUrl("https://example.invalid/r" + id + ".git");
        entity.setName("r" + id);
        entity.setBranch("main");
        return RepositoryView.of(entity);
    }

    private static AiReviewResultEntity written() {
        AiReviewResultEntity row = new AiReviewResultEntity();
        row.setModel("gemma4:12b-it-qat");
        row.setStatus("completed");
        return row;
    }
}
