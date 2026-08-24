package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.core.ZanshinContextTest;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Scans;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The scheduler against a database.
 *
 * <p>What a fake cannot show: that the stamp and the queued row survive together, that a second
 * tick does not stack a duplicate, and that the lease is really taken — the three behaviours
 * whose failure is a queue quietly filling with identical scans.
 */
@DisplayName("the periodic rescan, against a database")
class SchedulerDatabaseTest extends ZanshinContextTest {

    @Autowired
    private SchedulerService scheduler;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Test
    @DisplayName("a due target is queued once, and the second tick adds nothing")
    void aSecondTickDoesNotStack() {
        long id = due();

        assertThat(scheduler.runOnce(Instant.now())).isEqualTo(1);
        // Two ticks in a row is the ordinary case — the previous scan has not started yet.
        // Stacking would grow the queue without learning anything.
        assertThat(scheduler.runOnce(Instant.now())).isZero();
        assertThat(pendingFor(id)).hasSize(1);
    }

    @Test
    @DisplayName("the stamp is written even when nothing was queued")
    void theStampIsWrittenAnyway() {
        long id = due();
        scheduler.runOnce(Instant.now());
        Instant first = repositories.findById(id).orElseThrow().getLastScheduledScanAt();

        Instant later = Instant.now().plus(2, ChronoUnit.HOURS);
        scheduler.runOnce(later);

        // Stamping only on success would re-examine a target whose scan is dragging on every
        // single tick, for as long as it drags.
        assertThat(repositories.findById(id).orElseThrow().getLastScheduledScanAt()).isAfter(first);
    }

    @Test
    @DisplayName("a target whose interval has not elapsed is untouched")
    void anUndueTargetIsLeftAlone() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/slow.git");
        repository.setBranch("main");
        repository.setScanIntervalMinutes(1440);
        repository.setLastScheduledScanAt(Instant.now());
        long id = repositories.save(repository).getId();

        assertThat(scheduler.runOnce(Instant.now())).isZero();
        assertThat(pendingFor(id)).isEmpty();
    }

    @Test
    @DisplayName("the queued row carries the branch and the required label")
    void theQueuedRowIsComplete() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/labelled.git");
        repository.setBranch("develop");
        repository.setScanIntervalMinutes(60);
        repository.setRequiredAgentLabel("production");
        repository.setLastScheduledScanAt(Instant.now().minus(2, ChronoUnit.HOURS));
        long id = repositories.save(repository).getId();

        scheduler.runOnce(Instant.now());

        // Forgetting the label on this path alone would make targeting true "except for
        // scheduled scans" — which is false, and silent.
        assertThat(pendingFor(id)).singleElement().satisfies(scan -> {
            assertThat(scan.getBranch()).isEqualTo("develop");
            assertThat(scan.getRequiredAgentLabel()).isEqualTo("production");
        });
    }

    private long due() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/due-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        repository.setScanIntervalMinutes(60);
        repository.setLastScheduledScanAt(Instant.now().minus(2, ChronoUnit.HOURS));
        return repositories.save(repository).getId();
    }

    private List<ScanEntity> pendingFor(long repoId) {
        return scans.findAll().stream()
                .filter(scan -> repoId == scan.getRepoId())
                .filter(scan -> ScanStatus.PENDING.wireName().equals(scan.getStatus()))
                .toList();
    }
}
