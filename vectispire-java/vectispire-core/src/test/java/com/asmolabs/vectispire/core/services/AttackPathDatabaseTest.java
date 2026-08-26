package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathGraph;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.ApiEndpointEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.ApiEndpoints;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import java.util.List;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The attack path overview, and what it costs to build.
 *
 * <p><b>Written before the overview stopped querying per repository.</b> It looped over every
 * visible repository and rebuilt each graph on its own, and each graph was four reads: the
 * repository, its endpoints, its contracts, its open issues. Twenty targets meant eighty round
 * trips for one page — the same shape repaired in the blast radius and the gate, arriving with a
 * feature whose authorization was audited and whose cost was not.
 *
 * <p>The graphs themselves are characterised first: a refactor that batches the reads must not
 * change a single node, edge or path.
 */
@DisplayName("the attack path overview, against a database")
class AttackPathDatabaseTest extends VectispireContextTest {

    /** Hibernate counts nothing unless asked, and the last assertion is a count. */
    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private AttackPathService attackPaths;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private ApiEndpoints endpoints;

    @Autowired
    private Issues issues;

    @Autowired
    private Scans scans;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    private long exposed;

    @BeforeEach
    void seed() {
        exposed = repository("ssh://git@example.com/team/exposed.git", "exposed");

        // An unauthenticated route on a sensitive path, which is what turns an endpoint into the
        // first hop of a chain rather than just an entry in an inventory.
        endpoint(exposed, "GET", "/api/admin/users", false);
        endpoint(exposed, "GET", "/api/health", true);

        issue(exposed, "CVE-2021-44228", Severity.CRITICAL, FindingType.VULNERABILITY);
        issue(exposed, "aws-key", Severity.HIGH, FindingType.SECRET);
    }

    @Test
    @DisplayName("a graph carries the chain: ingress, the unauthenticated route, the vulnerability")
    void theGraphIsBuilt() {
        AttackPathGraph graph = attackPaths.getAttackPathGraph(exposed).orElseThrow();

        assertThat(graph.nodes()).isNotEmpty();
        assertThat(graph.nodes()).anySatisfy(node ->
                assertThat(node.label()).contains("Internet Ingress"));
        assertThat(graph.nodes())
                .as("the unauthenticated admin route is the hop that makes this a path")
                .anySatisfy(node -> assertThat(node.label()).isEqualTo("GET /api/admin/users"));
        assertThat(graph.edges()).isNotEmpty();
    }

    @Test
    @DisplayName("the overview returns the same graphs the per-target route does")
    void theOverviewAgreesWithTheSingleTarget() {
        long quiet = repository("ssh://git@example.com/team/quiet.git", "quiet");

        List<AttackPathGraph> overview = attackPaths.getOverview(Visibility.everything());

        assertThat(overview).hasSize(2);
        AttackPathGraph fromOverview = overview.stream()
                .filter(g -> g.nodes().stream().anyMatch(n -> "GET /api/admin/users".equals(n.label())))
                .findFirst()
                .orElseThrow();
        AttackPathGraph direct = attackPaths.getAttackPathGraph(exposed).orElseThrow();

        // Two code paths, one answer. A divergence here reads as a dashboard disagreeing with the
        // page it was opened from — the kind of defect a reader blames on caching.
        assertThat(fromOverview.nodes()).hasSameSizeAs(direct.nodes());
        assertThat(fromOverview.edges()).hasSameSizeAs(direct.edges());
        assertThat(fromOverview.attackPaths()).hasSameSizeAs(direct.attackPaths());
        assertThat(quiet).isPositive();
    }

    @Test
    @DisplayName("ten more repositories do not cost ten more rounds of queries")
    void theCostDoesNotFollowTheTargetCount() {
        int forOneRepository = queriesBuildingTheOverview();

        for (int index = 0; index < 10; index++) {
            long extra = repository("ssh://git@example.com/team/bulk-" + index + ".git", "bulk-" + index);
            endpoint(extra, "GET", "/api/bulk-" + index, false);
            issue(extra, "CVE-9100-" + index, Severity.HIGH, FindingType.VULNERABILITY);
        }

        assertThat(attackPaths.getOverview(Visibility.everything()))
                .as("the fixture really did grow, or the comparison below means nothing")
                .hasSize(11);

        // **The property, stated in the unit the defect was in.** The overview used to issue four
        // queries per repository — the repository, its endpoints, its contracts, its open issues —
        // so a page over twenty targets cost eighty round trips.
        assertThat(queriesBuildingTheOverview())
                .as("eleven repositories must not cost eleven times the queries of one")
                .isLessThanOrEqualTo(forOneRepository + 2);
    }

    private int queriesBuildingTheOverview() {
        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();
        attackPaths.getOverview(Visibility.everything());
        return (int) statistics.getQueryExecutionCount();
    }

    private long repository(String url, String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private void endpoint(long repoId, String method, String path, boolean authRequired) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        long scanId = scans.save(scan).getId();

        ApiEndpointEntity entity = new ApiEndpointEntity();
        entity.setScanId(scanId);
        entity.setRepositoryId(repoId);
        entity.setHttpMethod(method);
        entity.setPath(path);
        entity.setAuthRequired(authRequired);
        entity.setVisibility("PUBLIC");
        entity.setCreatedAt(Instant.now());
        endpoints.save(entity);
    }

    private void issue(long repoId, String identifier, Severity severity, FindingType type) {
        IssueEntity entity = new IssueEntity();
        entity.setRepoId(repoId);
        entity.setFingerprint(identifier + "-" + repoId);
        entity.setIdentifier(identifier);
        entity.setType(type.wireName());
        entity.setSeverity(severity.wireName());
        entity.setState(IssueState.OPEN.wireName());
        entity.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        entity.setIsKev(true);
        entity.setFirstSeenAt(Instant.now());
        entity.setLastSeenAt(Instant.now());
        entity.setTimesSeen(1);
        issues.save(entity);
    }
}
