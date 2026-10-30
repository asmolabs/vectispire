package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.scanning.persistence.queries.NewestCompletedScanRow;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Query;

/**
 * Whether a scan holds its SBOM is asked of {@code has_sbom}, never of the document (V98).
 *
 * <p><b>The defect this closes.</b> Ten queries tested {@code sbom is null} or {@code is not null} —
 * the licence tallies' census, the inventory's scans, each target's newest completed scan — and MySQL
 * reads a {@code longtext} back from its off-page storage to test it for null: on the 1.0.0-rc.1 load
 * test's estate (900 scans of 340 KB) each of those statements took 500 ms against 0.3 ms for a count
 * over the same rows, twice in each licence, scorecard and posture call. No statement count or row
 * count sees it — the rows are the same — so this pins the two things that make the fix one: no query
 * of {@link ScanRepository} tests the document for null, and the flag the queries read instead follows
 * the document through every way it is written and erased.
 */
@DisplayName("whether a scan holds its SBOM")
class ScanPayloadFlagDatabaseTest extends VectispireContextTest {

    /** A null test on the document, in any spelling JPQL accepts: {@code s.sbom is null}, {@code sbom is not null}. */
    private static final Pattern NULL_TEST_ON_THE_DOCUMENT =
            Pattern.compile("\\bsbom\\s+is\\s+(not\\s+)?null", Pattern.CASE_INSENSITIVE);

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Test
    @DisplayName("no query tests the document itself for null")
    void noQueryReadsTheDocumentToTestIt() {
        List<String> offenders = new ArrayList<>();
        for (Method method : ScanRepository.class.getMethods()) {
            Query query = method.getAnnotation(Query.class);
            if (query != null && NULL_TEST_ON_THE_DOCUMENT.matcher(query.value()).find()) {
                offenders.add(method.getName());
            }
        }
        assertThat(offenders)
                .as("ask s.hasSbom: on MySQL a null test on the longtext reads every SBOM stored")
                .isEmpty();
    }

    @Test
    @DisplayName("the flag follows the document: written by the ingestion, erased by the retention purge")
    void theFlagFollowsTheDocument() {
        long repo = repository();
        long bare = scan(repo, null, "2026-09-01T10:00:00Z");
        long kept = scan(repo, "{\"artifacts\":[]}", "2026-09-02T10:00:00Z");
        long purged = scan(repo, "{\"artifacts\":[]}", "2026-09-03T10:00:00Z");

        assertThat(withSbom(repo)).containsExactlyInAnyOrder(kept, purged);
        assertThat(sbomStored(repo)).as("the newest completed scan, before the purge").isTrue();
        assertThat(scansHoldingAnSbom(repo)).isEqualTo(2);

        // The retention purge's bulk update, which no entity sees: the engine recomputes the flag.
        scans.dropPayloads(List.of(purged));

        assertThat(withSbom(repo)).containsExactly(kept);
        assertThat(sbomStored(repo)).as("the newest completed scan, its SBOM purged").isFalse();
        assertThat(scansHoldingAnSbom(repo)).isEqualTo(1);

        // And an entity written through the persistence context, as the ingestion writes it.
        ScanEntity later = scans.findById(bare).orElseThrow();
        later.setSbom("{\"artifacts\":[]}");
        scans.saveAndFlush(later);
        assertThat(withSbom(repo)).containsExactlyInAnyOrder(kept, bare);
    }

    /** This repository's scans holding an SBOM: the database is shared by the JVM's other cases. */
    private List<Long> withSbom(long repo) {
        return scans.idsAndTargetsWithSbom().stream()
                .filter(row -> row[1] != null && ((Number) row[1]).longValue() == repo)
                .map(row -> ((Number) row[0]).longValue())
                .toList();
    }

    private boolean sbomStored(long repo) {
        List<NewestCompletedScanRow> rows =
                scans.findNewestWithStatusOfRepositories(List.of(repo), ScanStatus.COMPLETED.wireName());
        assertThat(rows).hasSize(1);
        return rows.getFirst().sbomStored();
    }

    private long scansHoldingAnSbom(long repo) {
        return scans.censusByTargetAndStatus().stream()
                .filter(row -> row[0] != null && ((Number) row[0]).longValue() == repo)
                .mapToLong(row -> ((Number) row[5]).longValue())
                .sum();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/flag.git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long scan(long repoId, String sbom, String createdAt) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setSbom(sbom);
        scan.setCreatedAt(Instant.parse(createdAt));
        return scans.saveAndFlush(scan).getId();
    }
}
