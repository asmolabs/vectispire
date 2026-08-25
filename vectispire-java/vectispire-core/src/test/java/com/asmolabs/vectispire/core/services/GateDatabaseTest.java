package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.gate.RequestedPolicy;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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
    private GitRepositories repositories;

    @Autowired
    private Containers containers;

    @Autowired
    private Issues issues;

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
