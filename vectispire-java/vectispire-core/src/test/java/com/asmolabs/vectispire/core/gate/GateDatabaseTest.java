package com.asmolabs.vectispire.core.gate;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.gate.GateVerdict;
import com.asmolabs.vectispire.common.domain.gate.Observation;
import com.asmolabs.vectispire.common.domain.gate.RequestedPolicy;
import com.asmolabs.vectispire.common.domain.gate.SecurityOverview;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import java.util.List;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The verdict a pipeline gets, and what it costs to produce.
 *
 * <p><b>Written before the gate stopped reading the whole estate.</b> {@code evaluate} asked for
 * one target and called {@code findByState("open")}: every open issue in the deployment, mapped
 * into a per-target map, of which one entry was kept and the rest discarded. On the endpoint every
 * pipeline calls on every build, against a column carrying no index.
 *
 * <p>There was no service-level coverage at all — only {@code GatePoliciesRoutesTest}, which is
 * about storing policies. So the verdicts below are a <em>characterisation</em>: what the old code
 * answered on this fixture. A refactor that changes a number has to change one here first, by hand.
 *
 * <p>The last test is the one that matters most, and it is stated in the unit the defect was
 * actually in: not queries — the old code issued two and the new one issues two — but <b>rows
 * loaded</b>. A gate whose cost tracks the estate rather than the target is the thing that must not
 * come back.
 */
@DisplayName("the quality gate, against a database")
class GateDatabaseTest extends VectispireContextTest {

    /** Hibernate counts nothing unless asked, and the last assertion is a count. */
    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private GateService gate;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    private ScanTarget audited;
    private ScanTarget neighbour;
    private ScanTarget image;

    @BeforeEach
    void seed() {
        audited = new ScanTarget.Repository(repository("ssh://git@example.com/team/audited.git", "audited"));
        neighbour = new ScanTarget.Repository(repository("ssh://git@example.com/team/neighbour.git", "neighbour"));
        image = new ScanTarget.Container(container("registry.example.com", "team/service", "1.4.0"));

        issue(audited, "fp-a1", Severity.CRITICAL, IssueState.OPEN);
        issue(audited, "fp-a2", Severity.LOW, IssueState.OPEN);
        issue(audited, "fp-a3", Severity.CRITICAL, IssueState.RESOLVED);

        // The neighbour is loud. Nothing it carries may reach the audited target's verdict — this
        // is the property a per-target query has to preserve, and the one a shared map could lose.
        for (int index = 0; index < 5; index++) {
            issue(neighbour, "fp-n" + index, Severity.CRITICAL, IssueState.OPEN);
        }

        issue(image, "fp-i1", Severity.HIGH, IssueState.OPEN);

        // Attached to nothing: a row the old grouping silently dropped, and which must stay
        // dropped rather than landing on whichever target is asked for next.
        issue(null, "fp-orphan", Severity.CRITICAL, IssueState.OPEN);
    }

    @Test
    @DisplayName("a target is judged on its own open issues and nobody else's")
    void oneTargetsOwnIssues() {
        assertThat(gate.evaluate(audited, RequestedPolicy.none()).verdict().evaluated())
                .as("two open issues on this repository — not the resolved third, not the neighbour's five")
                .isEqualTo(2);

        assertThat(gate.evaluate(neighbour, RequestedPolicy.none()).verdict().evaluated()).isEqualTo(5);

        assertThat(gate.evaluate(image, RequestedPolicy.none()).verdict().evaluated())
                .as("a container is the second nullable key, and a repository-only fixture never exercises it")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("a target nobody has filed anything against is judged on nothing")
    void aQuietTarget() {
        ScanTarget quiet = new ScanTarget.Repository(repository("ssh://git@example.com/team/quiet.git", "quiet"));
        // Examined and clean: "nothing filed" is a pass only once a scan has looked.
        scan(quiet, ScanStatus.COMPLETED);

        // Zero, not "whatever the map's default happened to be": a quiet target inheriting the
        // orphan row, or another target's group, would fail a build for somebody else's finding.
        assertThat(gate.evaluate(quiet, RequestedPolicy.none()).verdict().evaluated()).isZero();
        assertThat(gate.evaluate(quiet, RequestedPolicy.none()).verdict().passed()).isTrue();
    }

    @Test
    @DisplayName("the verdict itself, not only its count")
    void theVerdict() {
        assertThat(gate.evaluate(audited, RequestedPolicy.none()).verdict().countsBySeverity())
                .containsEntry(Severity.CRITICAL, 1L)
                .containsEntry(Severity.LOW, 1L);
    }

    @Test
    @DisplayName("a noisier estate does not make one target's gate more expensive")
    void theCostFollowsTheTargetNotTheEstate() {
        scan(audited, ScanStatus.COMPLETED);
        int onASmallEstate = entitiesLoadedEvaluating();

        // Three hundred issues, none of them on the audited target. Its verdict is unchanged, so
        // any extra row loaded is a row the answer did not need.
        for (int index = 0; index < 300; index++) {
            issue(neighbour, "fp-bulk-" + index, Severity.HIGH, IssueState.OPEN);
        }
        assertThat(gate.evaluate(audited, RequestedPolicy.none()).verdict().evaluated())
                .as("the fixture grew around the target, not on it")
                .isEqualTo(2);

        assertThat(entitiesLoadedEvaluating())
                .as("three hundred issues elsewhere must not be loaded to judge this target")
                .isLessThanOrEqualTo(onASmallEstate);

        assertThat(entitiesLoadedEvaluating())
                .as("whatever the estate holds, one verdict reads a bounded number of rows")
                .isLessThanOrEqualTo(20);
    }

    /**
     * Whether a scan examined the target, read from the scans table by the query the endpoint runs.
     *
     * <p>The order of the scans is the identifier's, as everywhere a "newest" is read, so each case
     * writes its scans oldest first.
     */
    @Nested
    @DisplayName("a target no finished scan examined")
    class Unexamined {

        @Test
        @DisplayName("is refused when it was never scanned, whatever its backlog")
        void neverScanned() {
            // The audited repository carries two open issues and no scan: an import or a fixture
            // is not an examination, and neither is the empty backlog of a target nobody looked at.
            GateVerdict verdict = gate.evaluate(audited, RequestedPolicy.none()).verdict();

            assertThat(verdict.passed()).isFalse();
            assertThat(verdict.violations().getFirst().rule()).isEqualTo(GateVerdict.Rule.OBSERVATION);
            assertThat(verdict.violations().getFirst().reason()).contains("never examined");
        }

        @Test
        @DisplayName("is refused while its only scans are pending or running")
        void onlyInFlight() {
            ScanTarget fresh = new ScanTarget.Repository(repository("ssh://git@example.com/team/fresh.git", "fresh"));
            scan(fresh, ScanStatus.PENDING);
            scan(fresh, ScanStatus.SCANNING);

            assertThat(rules(fresh)).containsExactly(GateVerdict.Rule.OBSERVATION);
        }

        @Test
        @DisplayName("is refused when the newest finished scan failed, an earlier completed one notwithstanding")
        void lastFinishedFailed() {
            ScanTarget broken = new ScanTarget.Repository(repository("ssh://git@example.com/team/broken.git", "broken"));
            scan(broken, ScanStatus.COMPLETED);
            scan(broken, ScanStatus.FAILED);
            // A retry queued behind the failure is not an examination yet either.
            scan(broken, ScanStatus.PENDING);

            GateVerdict verdict = gate.evaluate(broken, RequestedPolicy.none()).verdict();

            assertThat(verdict.passed()).isFalse();
            assertThat(verdict.violations()).singleElement().satisfies(violation -> {
                assertThat(violation.rule()).isEqualTo(GateVerdict.Rule.OBSERVATION);
                assertThat(violation.reason()).contains("last scan of this target failed");
            });
        }

        @Test
        @DisplayName("an image is read by its own column")
        void anImageThatFailed() {
            scan(image, ScanStatus.FAILED);

            assertThat(rules(image)).first().isEqualTo(GateVerdict.Rule.OBSERVATION);
        }

        @Test
        @DisplayName("passes once a scan completed after the failure, and stays passing while the next one runs")
        void examinedAgain() {
            ScanTarget mended = new ScanTarget.Repository(repository("ssh://git@example.com/team/mended.git", "mended"));
            scan(mended, ScanStatus.FAILED);
            scan(mended, ScanStatus.COMPLETED);
            scan(mended, ScanStatus.SCANNING);

            assertThat(gate.evaluate(mended, RequestedPolicy.none()).verdict().passed()).isTrue();
        }

        @Test
        @DisplayName("is not examined by another target's scan")
        void notByTheNeighbour() {
            scan(neighbour, ScanStatus.COMPLETED);

            assertThat(rules(audited)).first().isEqualTo(GateVerdict.Rule.OBSERVATION);
        }

        @Test
        @DisplayName("is failing on the security screen too, on the same reading")
        void theOverviewAgrees() {
            // Targets with no issue at all, so that only the examination can fail them.
            ScanTarget unscanned =
                    new ScanTarget.Repository(repository("ssh://git@example.com/team/unscanned.git", "unscanned"));
            ScanTarget broken = new ScanTarget.Container(container("registry.example.com", "team/broken", "2.0"));
            scan(broken, ScanStatus.COMPLETED);
            scan(broken, ScanStatus.FAILED);
            ScanTarget mended = new ScanTarget.Repository(repository("ssh://git@example.com/team/mended.git", "mended"));
            scan(mended, ScanStatus.COMPLETED);
            scan(mended, ScanStatus.SCANNING);

            SecurityOverview.Overview overview = gate.overview(Visibility.everything());

            assertThat(posture(overview, unscanned).passed()).as("never scanned").isFalse();
            assertThat(posture(overview, broken).passed()).as("last scan failed").isFalse();
            assertThat(posture(overview, mended).passed())
                    .as("examined, its re-scan running — the verdict is the examination's")
                    .isTrue();
            assertThat(posture(overview, mended).observation()).isEqualTo(Observation.IN_PROGRESS);
            for (ScanTarget target : List.of(unscanned, broken, mended)) {
                assertThat(posture(overview, target).passed())
                        .as("the screen's verdict is the endpoint's, for " + target)
                        .isEqualTo(gate.evaluate(target, RequestedPolicy.none()).verdict().passed());
            }
        }

        private List<GateVerdict.Rule> rules(ScanTarget target) {
            return gate.evaluate(target, RequestedPolicy.none()).verdict().violations().stream()
                    .map(GateVerdict.Violation::rule)
                    .toList();
        }

        private SecurityOverview.TargetPosture posture(SecurityOverview.Overview overview, ScanTarget target) {
            return overview.targets().stream().filter(posture -> posture.target().equals(target)).findFirst().orElseThrow();
        }
    }

    private void scan(ScanTarget target, ScanStatus status) {
        ScanEntity scan = new ScanEntity();
        switch (target) {
            case ScanTarget.Repository repository -> scan.setRepoId(repository.id());
            case ScanTarget.Container container -> scan.setContainerId(container.id());
        }
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(Instant.now());
        scans.save(scan);
    }

    private int entitiesLoadedEvaluating() {
        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();
        gate.evaluate(audited, RequestedPolicy.none());
        return (int) statistics.getEntityLoadCount();
    }

    private long repository(String url, String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private long container(String registry, String name, String tag) {
        ContainerEntity entity = new ContainerEntity();
        entity.setRegistry(registry);
        entity.setImageName(name);
        entity.setTag(tag);
        return containers.save(entity).getId();
    }

    private void issue(ScanTarget target, String fingerprint, Severity severity, IssueState state) {
        IssueEntity entity = new IssueEntity();
        switch (target) {
            case ScanTarget.Repository repository -> entity.setRepoId(repository.id());
            case ScanTarget.Container image -> entity.setContainerId(image.id());
            case null -> { }
        }
        entity.setFingerprint(fingerprint);
        entity.setIdentifier(fingerprint.toUpperCase(java.util.Locale.ROOT));
        entity.setType(FindingType.VULNERABILITY.wireName());
        entity.setSeverity(severity.wireName());
        entity.setState(state.wireName());
        entity.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        entity.setIsKev(false);
        entity.setFirstSeenAt(Instant.now());
        entity.setLastSeenAt(Instant.now());
        entity.setTimesSeen(1);
        issues.save(entity);
    }
}
