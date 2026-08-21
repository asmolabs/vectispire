package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.access.VisibilityMode;
import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.services.SettingsService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * What a team grants, through the routes an administrator really uses.
 *
 * <p>{@code VisibilityRoutesTest} covers the per-account assignment beside this. The cases worth
 * their own suite are the ones only teams have: that membership grants what the team owns, that
 * it stops granting when either half is removed, and — the one that would be a disclosure —
 * that an account in <b>no</b> team still sees nothing rather than everything, since the query
 * behind that answer is an {@code in} clause whose empty form matches every row on some engines.
 */
@DisplayName("what a team grants")
class TeamVisibilityTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("a member sees what the team owns, and nothing else")
    void membershipGrantsTheTeamsTargets() throws Exception {
        restrict();
        long ours = repository("https://example.invalid/ours.git");
        long theirs = repository("https://example.invalid/theirs.git");
        issue(ours, "CVE-OURS");
        issue(theirs, "CVE-THEIRS");

        String reader = asReader();
        long team = createTeam(uniqueName());
        assign(team, ours);
        addMember(team, readerId());

        mvc.perform(authenticated(get("/api/v1/issues"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.items[0].identifier").value("CVE-OURS"));
        mvc.perform(authenticated(get("/api/v1/repositories"), reader))
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    @DisplayName("an account in no team sees nothing, not everything")
    void aTeamlessAccountSeesNothing() throws Exception {
        restrict();
        long ours = repository("https://example.invalid/ours.git");
        issue(ours, "CVE-OURS");

        // A team exists and owns the repository; the reader is simply not in it. The query that
        // answers this is `team_id in (…)`, and its empty form is a syntax error on some engines
        // and matches every row on others — so the service short-circuits before asking. This is
        // the test that would catch that guard being removed.
        long team = createTeam(uniqueName());
        assign(team, ours);

        mvc.perform(authenticated(get("/api/v1/issues"), asReader()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(0));
    }

    @Test
    @DisplayName("team and direct assignment add up rather than narrow each other")
    void theTwoRoutesAreUnioned() throws Exception {
        restrict();
        long viaTeam = repository("https://example.invalid/team.git");
        long viaAssignment = repository("https://example.invalid/direct.git");
        issue(viaTeam, "CVE-TEAM");
        issue(viaAssignment, "CVE-DIRECT");

        String reader = asReader();
        long team = createTeam(uniqueName());
        assign(team, viaTeam);
        addMember(team, readerId());
        assignDirectly(readerId(), viaAssignment);

        // Intersecting the two would mean that joining a team *narrows* what somebody already
        // had, so an administrator adding a member would silently revoke. Both are visible.
        mvc.perform(authenticated(get("/api/v1/issues"), reader))
                .andExpect(jsonPath("$.total").value(2));
    }

    @Test
    @DisplayName("removing the member, or the target, removes the access")
    void revocationReallyRevokes() throws Exception {
        restrict();
        long ours = repository("https://example.invalid/ours.git");
        issue(ours, "CVE-OURS");

        String reader = asReader();
        long team = createTeam(uniqueName());
        assign(team, ours);
        addMember(team, readerId());
        mvc.perform(authenticated(get("/api/v1/issues"), reader)).andExpect(jsonPath("$.total").value(1));

        // Both halves are replaced wholesale by design — a server that only ever added would
        // make a revocation a no-op that looks like a success.
        mvc.perform(authenticated(put("/api/v1/teams/" + team + "/members"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of())))
                .andExpect(status().isOk());
        mvc.perform(authenticated(get("/api/v1/issues"), reader)).andExpect(jsonPath("$.total").value(0));

        addMember(team, readerId());
        mvc.perform(authenticated(put("/api/v1/teams/" + team + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of())))
                .andExpect(status().isOk());
        mvc.perform(authenticated(get("/api/v1/issues"), reader)).andExpect(jsonPath("$.total").value(0));
    }

    @Test
    @DisplayName("deleting the team takes its grants with it")
    void deletingATeamRevokes() throws Exception {
        restrict();
        long ours = repository("https://example.invalid/ours.git");
        issue(ours, "CVE-OURS");

        String reader = asReader();
        long team = createTeam(uniqueName());
        assign(team, ours);
        addMember(team, readerId());

        mvc.perform(authenticated(delete("/api/v1/teams/" + team), asAdmin()))
                .andExpect(status().isNoContent());

        // By the database's cascade, which is why the memberships and assignments are real
        // foreign keys and not a pair of columns.
        mvc.perform(authenticated(get("/api/v1/issues"), reader)).andExpect(jsonPath("$.total").value(0));
    }

    @Test
    @DisplayName("deleting a target clears the rows that name it")
    void deletingATargetClearsItsAssignments() throws Exception {
        restrict();
        long doomed = repository("https://example.invalid/doomed.git");
        long team = createTeam(uniqueName());
        assign(team, doomed);

        mvc.perform(authenticated(delete("/api/v1/repositories/" + doomed), asAdmin()))
                .andExpect(status().isNoContent());

        // Not tidiness: `(target_kind, target_id)` cascades from nothing, and SQLite reuses a
        // freed rowid — a stale row would come to name whichever repository is created next.
        mvc.perform(authenticated(get("/api/v1/teams/" + team + "/targets"), asAdmin()))
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    @DisplayName("two teams cannot share a name, whatever the casing")
    void namesAreUniqueCaseInsensitively() throws Exception {
        String name = uniqueName();
        createTeam(name);

        // The unique constraint on the column would accept the same name in another casing: to
        // everybody reading the screen those are one team, and two of them make every assignment
        // a guess.
        mvc.perform(authenticated(post("/api/v1/teams"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name.toUpperCase(java.util.Locale.ROOT)))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("a reader cannot administer teams")
    void teamsAreAdministrativeOnly() throws Exception {
        long team = createTeam(uniqueName());

        // The whole point of the feature is that it decides what people read, so being able to
        // edit it is administration. Checked at the entry point, like every other route.
        mvc.perform(authenticated(get("/api/v1/teams"), asReader())).andExpect(status().isForbidden());
        mvc.perform(authenticated(put("/api/v1/teams/" + team + "/members"), asReader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(1))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a membership for an account that does not exist is refused")
    void unknownMembersAreRefused() throws Exception {
        long team = createTeam(uniqueName());

        // Silently dropping it would make the saved result differ from what the screen sent,
        // with nobody told which of the two is now true.
        mvc.perform(authenticated(put("/api/v1/teams/" + team + "/members"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(987654L))))
                .andExpect(status().isBadRequest());
    }

    /**
     * A name no other test method has used.
     *
     * <p>The base class shares one database across the methods of a suite — which is what makes
     * them fast — so a fixed name is taken by whichever test ran first, and the failure looks
     * like a broken uniqueness rule rather than like shared state.
     */
    private static String uniqueName() {
        return "team-" + System.nanoTime();
    }

    private void restrict() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
    }

    private long createTeam(String name) throws Exception {
        String body = mvc.perform(authenticated(post("/api/v1/teams"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name))))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return json.readTree(body).path("id").asLong();
    }

    private void assign(long teamId, long repositoryId) throws Exception {
        mvc.perform(authenticated(put("/api/v1/teams/" + teamId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "repository", "id", repositoryId)))))
                .andExpect(status().isOk());
    }

    private void addMember(long teamId, long userId) throws Exception {
        mvc.perform(authenticated(put("/api/v1/teams/" + teamId + "/members"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(userId))))
                .andExpect(status().isOk());
    }

    private void assignDirectly(long userId, long repositoryId) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "repository", "id", repositoryId)))))
                .andExpect(status().isOk());
    }

    /** The reader account's identifier, read back through the administration listing. */
    private long readerId() throws Exception {
        String body = mvc.perform(authenticated(get("/api/v1/users"), asAdmin()))
                .andReturn()
                .getResponse()
                .getContentAsString();
        for (var node : json.readTree(body).path("users")) {
            if (node.path("username").asText("").startsWith("reader-")) {
                return node.path("id").asLong();
            }
        }
        throw new IllegalStateException("no reader account in the listing");
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void issue(long repoId, String identifier) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
