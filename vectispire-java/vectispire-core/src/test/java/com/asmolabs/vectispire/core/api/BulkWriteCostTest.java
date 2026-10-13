package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.TeamEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Two requests whose statements followed the size of their answer: a bulk triage and the SCIM group
 * listing. Measured with Hibernate's counters, as {@link ReadCostSweepTest} measures the reads.
 *
 * <p><b>What is compared is a small call and a large one</b>, not a count against a number chosen to
 * pass: the same request over 5 and 50 issues, over 3 and 30 teams. A bulk triage writes a row and a
 * history entry per issue, which is the job; reading each issue on its own, twice, was not — 1,000
 * reads for the 500 the screen can select. The SCIM listing read each team's members in a statement of
 * its own and every account whole to print a name.
 *
 * <p>Queries are Hibernate's query executions, which a load by id is not; statements are every
 * statement prepared, which counts the update and the history row each triaged issue has to cost — and
 * the read of each issue by its id, which it does not.
 */
@DisplayName("a bulk triage and the SCIM group listing cost the same statements at any size")
class BulkWriteCostTest extends ApiTestBase {

    /** The counters are off in the shipped configuration, and are the whole instrument here. */
    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private TeamRepository teams;

    @Autowired
    private TeamMemberRepository members;

    @Autowired
    private UserRepository users;

    /** Statements of one request. */
    private record Cost(long queries, long statements, long accountsLoaded) {}

    @Test
    @DisplayName("triaging 50 issues reads them as triaging 5 does")
    void bulkTriage() throws Exception {
        long target = repository("https://example.invalid/bulk-cost.git");
        String admin = asAdmin();

        Cost few = triage(issues(target, "FEW", 5), admin);
        Cost many = triage(issues(target, "MANY", 50), admin);

        assertThat(many.queries()).as("queries, 5 issues then 50").isEqualTo(few.queries());
        // What 45 more issues may cost: their update and their history row, nothing read one by one.
        assertThat(many.statements() - few.statements())
                .as("statements added by 45 more issues (5 issues: %s, 50: %s)", few.statements(), many.statements())
                .isEqualTo(2L * 45);
    }

    @Test
    @DisplayName("listing 30 groups reads their members as listing 3 does, and no account whole")
    void scimGroups() throws Exception {
        String admin = asAdmin();
        teamsWithAMember("small", 3);
        Cost few = measure(() -> mvc.perform(authenticated(get("/scim/v2/Groups"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(3))
                .andExpect(jsonPath("$.Resources[0].members[0].display").value("small-member-0")));
        teamsWithAMember("large", 27);
        Cost many = measure(() -> mvc.perform(authenticated(get("/scim/v2/Groups"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(30)));

        assertThat(many.queries()).as("queries, 3 groups then 30").isEqualTo(few.queries());
        assertThat(many.accountsLoaded()).as("accounts loaded whole, 3 groups then 30")
                .isEqualTo(few.accountsLoaded());
    }

    private Cost triage(List<Long> ids, String token) throws Exception {
        return measure(() -> mvc.perform(authenticated(post("/api/v1/issues/triage")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("ids", ids, "status", "affected"))),
                        token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(ids.size())));
    }

    @FunctionalInterface
    private interface Call {
        ResultActions run() throws Exception;
    }

    private Cost measure(Call call) throws Exception {
        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();
        call.run();
        return new Cost(
                statistics.getQueryExecutionCount(),
                statistics.getPrepareStatementCount(),
                statistics.getEntityStatistics(UserEntity.class.getName()).getLoadCount());
    }

    private void teamsWithAMember(String prefix, int count) {
        for (int i = 0; i < count; i++) {
            UserEntity user = new UserEntity();
            user.setUsername(prefix + "-member-" + i);
            // Never signed in with: the listing only prints the name.
            user.setPassword("not-a-hash");
            user.setRole(Role.USER.name());
            user.setIsActive(true);
            user.setMustChangePassword(false);
            user.setCreatedAt(Instant.now());
            user.setUpdatedAt(Instant.now());
            long userId = users.save(user).getId();

            TeamEntity team = new TeamEntity();
            team.setName(prefix + "-team-" + i);
            team.setCreatedAt(Instant.now());
            long teamId = teams.save(team).getId();
            members.save(new TeamMemberEntity(teamId, userId, TeamMemberEntity.Origin.SCIM));
        }
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private List<Long> issues(long repoId, String prefix, int count) {
        return IntStream.range(0, count).mapToObj(i -> {
            IssueEntity issue = new IssueEntity();
            issue.setRepoId(repoId);
            issue.setFingerprint(prefix + "-" + i + "-" + repoId);
            issue.setType(FindingType.VULNERABILITY.wireName());
            issue.setIdentifier("CVE-COST-" + prefix + "-" + i);
            issue.setSeverity(Severity.HIGH.wireName());
            issue.setState(IssueState.OPEN.wireName());
            issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
            issue.setFirstSeenAt(Instant.now());
            issue.setLastSeenAt(Instant.now());
            issue.setTimesSeen(1);
            return issues.save(issue).getId();
        }).toList();
    }
}
