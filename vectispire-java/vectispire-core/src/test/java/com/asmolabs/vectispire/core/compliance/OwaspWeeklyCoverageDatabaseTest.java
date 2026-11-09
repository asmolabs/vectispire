package com.asmolabs.vectispire.core.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Split;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.State;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.compliance.OwaspWeeklyCoverageService.Outcome;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageEntity;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.TargetDeletionService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The weekly OWASP record, as a database produces it.
 *
 * <p>Three targets: {@code alpha}, scanned, with one open vulnerability awaiting triage, one accepted
 * as not affecting it and one accepted secret; {@code beta}, never scanned, with an open vulnerability
 * all the same; and an image with nothing at all. Between them they carry the three things the record
 * must not lose: an accepted risk shown apart, a target nobody examined, and a category nothing here
 * covers.
 */
@DisplayName("the weekly OWASP record, against a database")
class OwaspWeeklyCoverageDatabaseTest extends VectispireContextTest {

    /** A Wednesday: the week is the one starting on Monday 28 September 2026. */
    private static final Instant WEDNESDAY = Instant.parse("2026-09-30T10:00:00Z");
    private static final Instant WEEK = Instant.parse("2026-09-28T00:00:00Z");

    @Autowired
    private OwaspWeeklyCoverageService weekly;

    @Autowired
    private OwaspCoverageService coverage;

    @Autowired
    private OwaspWeeklyCoverageRepository rows;

    @Autowired
    private TargetDeletionService deletion;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ScanRepository scans;

    private long alpha;
    private long beta;
    private long image;
    private IssueEntity awaiting;

    @BeforeEach
    void seed() {
        alpha = repository("alpha");
        beta = repository("beta");
        image = container();
        scan(alpha);

        awaiting = issue(alpha, "fp-open", FindingType.VULNERABILITY, TriageStatus.UNDER_REVIEW);
        issue(alpha, "fp-accepted", FindingType.VULNERABILITY, TriageStatus.NOT_AFFECTED);
        issue(alpha, "fp-secret", FindingType.SECRET, TriageStatus.NOT_AFFECTED);
        issue(beta, "fp-beta", FindingType.VULNERABILITY, TriageStatus.UNDER_REVIEW);
    }

    @Test
    @DisplayName("one target's grid counts the settled findings apart, and keeps the grid's state")
    void oneTargetSettledApart() {
        List<Split> lines = coverage.ofTarget(new ScanTarget.Repository(alpha), coverage.reading());

        assertThat(line(lines, "A06")).isEqualTo(new Split("A06", State.FINDINGS, 1, 1));
        // Its only secret is accepted: nothing open in the grid, and the record still says one was.
        assertThat(line(lines, "A07")).isEqualTo(new Split("A07", State.NO_FINDING, 0, 1));
        assertThat(line(lines, "A01").state())
                .as("nothing in this product looks for broken access control")
                .isEqualTo(State.NOT_COVERED);
    }

    @Test
    @DisplayName("a target never scanned reads unmeasured where it holds nothing, and its open findings are findings")
    void aNeverScannedTarget() {
        // The estate is scanned (alpha is); beta is not. Narrowed to beta, the grid must not borrow
        // alpha's scan: a category with nothing open is unmeasured, never clean. An open finding is a
        // fact whatever examined it, so its open vulnerability reads as one.
        List<Split> lines = coverage.ofTarget(new ScanTarget.Repository(beta), coverage.reading());

        assertThat(line(lines, "A06")).isEqualTo(new Split("A06", State.FINDINGS, 1, 0));
        assertThat(line(lines, "A07"))
                .as("nothing open, nothing examined: not \"nothing found\"")
                .isEqualTo(new Split("A07", State.NOT_MEASURED, 0, 0));
        assertThat(line(lines, "A01").state()).isEqualTo(State.NOT_COVERED);
    }

    @Test
    @DisplayName("records every target that exists, ten categories each, in the current week")
    void capturesEveryTarget() {
        assertThat(weekly.capture(WEDNESDAY)).isEqualTo(Outcome.CAPTURED);

        List<OwaspWeeklyCoverageEntity> week = rows.findAll();
        assertThat(week).hasSize(3 * 10).allSatisfy(row -> {
            assertThat(row.getWeekStart()).isEqualTo(WEEK);
            assertThat(row.getCapturedAt()).isEqualTo(WEDNESDAY);
        });
        assertThat(week).filteredOn(row -> row.getTargetKind().equals("container"))
                .hasSize(10)
                .allSatisfy(row -> assertThat(row.getTargetId()).isEqualTo(image));
        assertThat(row(week, "repository", alpha, "A06"))
                .returns("FINDINGS", OwaspWeeklyCoverageEntity::getState)
                .returns(1L, OwaspWeeklyCoverageEntity::getOpenCount)
                .returns(1L, OwaspWeeklyCoverageEntity::getSettledCount);
        assertThat(row(week, "repository", beta, "A07").getState())
                .as("a target nobody examined is recorded, and recorded as such")
                .isEqualTo("NOT_MEASURED");
    }

    @Test
    @DisplayName("writes the current week again only once six hours have passed")
    void theSixHourGate() {
        weekly.capture(WEDNESDAY);
        issues.delete(awaiting);

        assertThat(weekly.capture(WEDNESDAY.plus(Duration.ofHours(5).plusMinutes(59)))).isEqualTo(Outcome.NOT_DUE);
        assertThat(row(rows.findAll(), "repository", alpha, "A06"))
                .as("not rewritten inside the window: the figure is the first capture's")
                .returns(1L, OwaspWeeklyCoverageEntity::getOpenCount)
                .returns(WEDNESDAY, OwaspWeeklyCoverageEntity::getCapturedAt);

        Instant later = WEDNESDAY.plus(Duration.ofHours(6));
        assertThat(weekly.capture(later)).isEqualTo(Outcome.CAPTURED);
        assertThat(rows.findAll()).hasSize(30);
        assertThat(row(rows.findAll(), "repository", alpha, "A06"))
                .as("rewritten, not added to: one row per target, week and category")
                .returns(0L, OwaspWeeklyCoverageEntity::getOpenCount)
                .returns("NO_FINDING", OwaspWeeklyCoverageEntity::getState)
                .returns(later, OwaspWeeklyCoverageEntity::getCapturedAt);
    }

    @Test
    @DisplayName("a closed week keeps the state of its last capture; only the current one is written")
    void aPastWeekIsLeftAlone() {
        Instant lastWeek = WEDNESDAY.minus(Duration.ofDays(7));
        weekly.capture(lastWeek);
        issues.delete(awaiting);

        weekly.capture(WEDNESDAY);

        List<OwaspWeeklyCoverageEntity> all = rows.findAll();
        assertThat(all).hasSize(2 * 30);
        assertThat(all).filteredOn(row -> row.getWeekStart().equals(WEEK.minus(Duration.ofDays(7))))
                .hasSize(30)
                .allSatisfy(row -> assertThat(row.getCapturedAt()).isEqualTo(lastWeek));
        assertThat(row(rows.findByWeekStart(WEEK.minus(Duration.ofDays(7))), "repository", alpha, "A06").getOpenCount())
                .as("last week's figure is last week's, whatever happened since")
                .isEqualTo(1);
        assertThat(row(rows.findByWeekStart(WEEK), "repository", alpha, "A06").getOpenCount()).isZero();
    }

    @Test
    @DisplayName("a new week is written at once, whatever the age of the previous week's capture")
    void aNewWeekIsDue() {
        Instant sunday = Instant.parse("2026-09-27T23:00:00Z");
        weekly.capture(sunday);

        // Two hours later, but a week later too: the gate is asked of the week being written.
        assertThat(weekly.capture(sunday.plus(Duration.ofHours(2)))).isEqualTo(Outcome.CAPTURED);
        assertThat(rows.findByWeekStart(WEEK)).hasSize(30);
    }

    @Test
    @DisplayName("a deleted target's rows go with it, every week; the others stay")
    void theRowsGoWithTheTarget() {
        weekly.capture(WEDNESDAY.minus(Duration.ofDays(7)));
        weekly.capture(WEDNESDAY);

        deletion.deleteRepository(beta);
        deletion.deleteContainer(image);

        assertThat(rows.findAll())
                .hasSize(2 * 10)
                .allSatisfy(row -> assertThat(row.getTargetId()).isEqualTo(alpha));
    }

    @Test
    @DisplayName("the orphan sweep drops the rows of a target that no longer exists, and nothing else")
    void theSweepTakesTheOrphans() {
        weekly.capture(WEDNESDAY);
        // A capture reads the estate before it writes: a target deleted in between is written after
        // its purge ran. Simulated by a row naming a repository and an image nobody has.
        rows.save(orphan("repository", alpha + beta + image + 1_000));
        rows.save(orphan("container", alpha + beta + image + 1_000));

        deletion.purgeOrphanedTargetData();

        assertThat(rows.findAll()).hasSize(30);
    }

    private OwaspWeeklyCoverageEntity orphan(String kind, long id) {
        OwaspWeeklyCoverageEntity row = new OwaspWeeklyCoverageEntity();
        row.setWeekStart(WEEK);
        row.setTargetKind(kind);
        row.setTargetId(id);
        row.setCategory("A06");
        row.setState(OwaspCoverage.State.NO_FINDING.name());
        row.setCapturedAt(WEDNESDAY);
        return row;
    }

    private static Split line(List<Split> lines, String id) {
        return lines.stream().filter(line -> line.id().equals(id)).findFirst().orElseThrow();
    }

    private static OwaspWeeklyCoverageEntity row(List<OwaspWeeklyCoverageEntity> rows, String kind, long id, String category) {
        return rows.stream()
                .filter(row -> row.getTargetKind().equals(kind) && row.getTargetId() == id
                        && row.getCategory().equals(category))
                .findFirst()
                .orElseThrow();
    }

    private long repository(String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("ssh://git@example.com/team/" + name + ".git");
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private long container() {
        ContainerEntity entity = new ContainerEntity();
        entity.setImageName("registry.example.invalid/shop");
        entity.setTag("1.0.0");
        return containers.save(entity).getId();
    }

    /** A scan whose every step produced: a category reads clean only on what the latest scan recorded examining. */
    private void scan(long repoId) {
        ScanEntity entity = new ScanEntity();
        entity.setRepoId(repoId);
        entity.setStatus(ScanStatus.COMPLETED.wireName());
        entity.setExaminedTypes("vulnerability,secret,iac,license,eol,sast");
        entity.setDetectedLanguages("java");
        entity.setSastLanguages("java");
        entity.setBranch("main");
        entity.setCreatedAt(Instant.parse("2026-01-01T00:00:00Z"));
        scans.save(entity);
    }

    private IssueEntity issue(long repoId, String fingerprint, FindingType type, TriageStatus triage) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(fingerprint);
        issue.setType(type.wireName());
        issue.setIdentifier("rule." + fingerprint);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(triage.wireName());
        issue.setFirstSeenAt(Instant.parse("2026-01-01T00:00:00Z"));
        issue.setLastSeenAt(Instant.parse("2026-01-01T00:00:00Z"));
        issue.setTimesSeen(1);
        return issues.save(issue);
    }
}
