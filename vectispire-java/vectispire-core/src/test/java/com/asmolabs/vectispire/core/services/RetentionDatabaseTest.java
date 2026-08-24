package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The purge against a database.
 *
 * <p>Two claims a fake cannot make. The candidate query must come back <b>newest first</b> —
 * the ranking is what "keep the last N" means, and any other order purges exactly the scans the
 * payloads exist for. And the erased columns must come back as SQL {@code null}, not as a JSON
 * {@code null} literal, or the same rows are re-selected on every pass while the count reports
 * a job well done.
 */
@DisplayName("purging raw payloads, against a database")
class RetentionDatabaseTest extends VectispireContextTest {

    @Autowired
    private RetentionService retention;

    @Autowired
    private SettingsService settings;

    @Autowired
    private Scans scans;

    @Autowired
    private GitRepositories repositories;

    private long repositoryId;

    @BeforeEach
    void seed() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/kept.git");
        repository.setBranch("main");
        repositoryId = repositories.save(repository).getId();

        settings.set(Setting.RETENTION_KEEP_PER_TARGET, "2");
        settings.set(Setting.RETENTION_MAX_AGE_DAYS, "30");
    }

    @Test
    @DisplayName("the two most recent scans keep their payloads, the older ones lose them")
    void theKeepWindowIsTheMostRecent() {
        long oldest = withPayload(200);
        long middle = withPayload(100);
        long newest = withPayload(1);
        long second = withPayload(2);

        assertThat(retention.prune()).isEqualTo(2);

        assertThat(scans.findById(newest).orElseThrow().getSbom()).isNotNull();
        assertThat(scans.findById(second).orElseThrow().getSbom()).isNotNull();
        assertThat(scans.findById(middle).orElseThrow().getSbom()).isNull();
        assertThat(scans.findById(oldest).orElseThrow().getSbom()).isNull();
    }

    @Test
    @DisplayName("a purged row is not selected again on the next pass")
    void purgingIsNotRepeated() {
        withPayload(200);
        withPayload(100);
        withPayload(1);
        withPayload(2);

        assertThat(retention.prune()).isEqualTo(2);
        // The JSON-null trap: a column set to a JSON `null` literal satisfies `is not null`, so
        // the purge would re-select the same rows for ever and report a credible count each time.
        assertThat(retention.prune()).isZero();
        assertThat(retention.payloadCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("a scan outside the window but younger than the age limit is kept")
    void bothAxesMustAgree() {
        withPayload(1);
        withPayload(2);
        withPayload(3);

        // Three recent scans: outside the keep window, inside the age limit. Purging on either
        // axis alone would drop the third.
        assertThat(retention.prune()).isZero();
    }

    @Test
    @DisplayName("both settings at zero disables purging entirely")
    void zeroMeansNoLimitAndNotNoRetention() {
        settings.set(Setting.RETENTION_KEEP_PER_TARGET, "0");
        settings.set(Setting.RETENTION_MAX_AGE_DAYS, "0");
        withPayload(500);

        assertThat(retention.prune()).isZero();
    }

    private long withPayload(int daysAgo) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(Instant.now().minus(daysAgo, ChronoUnit.DAYS));
        scan.setSbom("{\"artifacts\":[]}");
        return scans.save(scan).getId();
    }
}
