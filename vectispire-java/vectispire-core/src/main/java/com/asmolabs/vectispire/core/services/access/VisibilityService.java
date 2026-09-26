package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.AgentEntity;
import com.asmolabs.vectispire.core.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.persistence.TeamTargetEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.persistence.UserTargetEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.TeamMembers;
import com.asmolabs.vectispire.core.repositories.TeamTargets;
import com.asmolabs.vectispire.core.repositories.UserTargets;
import com.asmolabs.vectispire.core.services.shared.SettingsService;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * What this caller may see, resolved once and asked everywhere.
 *
 * <p><b>One resolution point, one enforcement point.</b> The rule itself is {@link Visibility},
 * which is pure and exhaustively tested; this class only answers "which one applies to the
 * request in hand". Splitting it that way is what makes the interesting cases — an unassigned
 * account, an intersecting API key — testable without a database.
 *
 * <p><b>Administrators always see everything.</b> Not a convenience: somebody has to be able to
 * make the assignments, and an administrator who cannot see a target cannot assign it.
 *
 * <h2>Two ways to be allowed, and why both</h2>
 *
 * <p>An account sees the <b>union</b> of what its teams own and what was assigned to it
 * directly. The union is right here and the intersection is right one method below, which is
 * worth stating because the two are easy to swap:
 *
 * <ul>
 *   <li><b>Team plus direct assignment: union.</b> They answer the same question — what may this
 *       person read — from two directions. A team is the organisation; a direct assignment is
 *       the exception a team cannot express, one contractor on one repository. Intersecting them
 *       would mean joining a team <em>narrows</em> what somebody already had, so an
 *       administrator adding a team member would silently revoke.
 *   <li><b>Account and credential: intersection</b> ({@link #of(UserEntity, Visibility)}). Those
 *       answer different questions — who is this, and what is this key for. A narrow key held by
 *       a broad account must stay narrow.
 * </ul>
 *
 * <h2>A grant on a project is resolved here, and nowhere else</h2>
 *
 * <p>A grant may name a project (decision 0023). It is turned into the project's repositories
 * <b>at each request</b>, before anything is queried, so what leaves this class is still a set of
 * {@link ScanTarget}s: every query that narrows by visibility narrows a project's repositories
 * without knowing projects exist, and a refusal is still a 404. The cost is one query per request
 * for an account holding a project grant — the alternative, copying the project's repositories
 * into repository grants when the grant is made, is a snapshot, and a repository filed into the
 * project afterwards would stay invisible to exactly the people the project was granted to.
 */
@Service
public class VisibilityService {

    private final SettingsService settings;
    private final UserTargets assignments;
    private final TeamMembers memberships;
    private final TeamTargets teamTargets;
    private final GitRepositories repositories;

    public VisibilityService(
            SettingsService settings,
            UserTargets assignments,
            TeamMembers memberships,
            TeamTargets teamTargets,
            GitRepositories repositories) {
        this.settings = settings;
        this.assignments = assignments;
        this.memberships = memberships;
        this.teamTargets = teamTargets;
        this.repositories = repositories;
    }

    /**
     * What a caller may see, and which projects it was granted as such.
     *
     * <p>The second half is for the one reader that needs to know a grant named a project rather
     * than its repositories: the solutions tree, where a granted project appears even while it
     * holds no repository — a project somebody was given and cannot find is a support ticket.
     *
     * @param grantedProjects empty when the visibility is everything (there is nothing to add),
     *     and empty when the credential carries a restriction: a key narrowed to one repository
     *     reveals no project through its account's grants
     */
    public record Allowance(Visibility visibility, Set<Long> grantedProjects) {

        public Allowance {
            grantedProjects = Set.copyOf(grantedProjects);
        }
    }

    /** {@link #of(UserEntity, Visibility)}, with the projects granted as such beside it. */
    @Transactional(readOnly = true)
    public Allowance allowance(UserEntity user, Visibility restriction) {
        Allowance account = resolve(user);
        Visibility visibility = account.visibility().and(restriction);
        return new Allowance(
                visibility,
                restriction instanceof Visibility.Everything ? account.grantedProjects() : Set.of());
    }

    public VisibilityMode mode() {
        return VisibilityMode.of(settings.get(Setting.TARGET_VISIBILITY));
    }

    /**
     * The visibility of a signed-in account.
     *
     * @param restriction a further narrowing carried by the credential — none carries one today,
     *     see {@code VectispirePrincipal.credentialRestriction}. Intersected, never unioned: a
     *     narrow credential held by a broad account stays narrow
     */
    @Transactional(readOnly = true)
    public Visibility of(UserEntity user, Visibility restriction) {
        return accountVisibility(user).and(restriction);
    }

    @Transactional(readOnly = true)
    public Visibility of(UserEntity user) {
        return accountVisibility(user);
    }

    /**
     * An agent's visibility.
     *
     * <p>Everything, and deliberately: an agent does not read the backlog at all — its four
     * routes claim work and hand results back, and the work it is given is already narrowed by
     * the queue's own label routing. Restricting it here would express nothing and suggest the
     * agent protocol goes through these filters, which it does not.
     */
    public Visibility of(AgentEntity agent) {
        return Visibility.everything();
    }

    private Visibility accountVisibility(UserEntity user) {
        return resolve(user).visibility();
    }

    private Allowance resolve(UserEntity user) {
        if (user == null) {
            // No account, no visibility. Reached only if a route forgot its marker, and the safe
            // answer to "who is this" being unanswerable is "nothing".
            return new Allowance(Visibility.only(List.of()), Set.of());
        }
        if (mode() == VisibilityMode.EVERYONE || hasGlobalScope(user)) {
            return new Allowance(Visibility.everything(), Set.of());
        }

        // A set, not a list: a repository owned by two of the account's teams, or by a team and
        // directly, would otherwise be counted twice — harmless for `permits` and wrong for
        // anybody who reads the size of what a query was narrowed to.
        Set<ScanTarget> visible = new LinkedHashSet<>();
        Set<Long> projects = new LinkedHashSet<>();

        for (UserTargetEntity row : assignments.findByUserId(user.getId())) {
            collect(row.getId().targetKind(), row.getId().targetId(), visible, projects);
        }

        List<Long> teams = memberships.findByUserId(user.getId()).stream()
                .map(membership -> membership.getId().teamId())
                .toList();
        // **The guard, not an optimisation.** `in ()` is a syntax error on some engines and
        // matches every row on others, and "matches everything" here means an account in no team
        // sees the entire backlog. One `if` decides which of those two an unassigned account
        // gets, so it is not left to the driver.
        if (!teams.isEmpty()) {
            for (TeamTargetEntity row : teamTargets.findByTeamIdIn(teams)) {
                collect(row.getId().targetKind(), row.getId().targetId(), visible, projects);
            }
        }

        // The same guard, for the same reason, and it matters more here: `project_id in ()`
        // matching every row would hand an account with no project grant every repository that
        // has been filed anywhere. One query for all the granted projects, whether they came
        // directly or through teams — the union rule, applied before anything is read.
        if (!projects.isEmpty()) {
            for (Long repositoryId : repositories.findIdsByProjectIdIn(projects)) {
                visible.add(new ScanTarget.Repository(repositoryId));
            }
        }

        return new Allowance(Visibility.only(new ArrayList<>(visible)), projects);
    }

    private static void collect(String kind, Long id, Set<ScanTarget> visible, Set<Long> projects) {
        if (TeamRules.KIND_PROJECT.equals(kind)) {
            projects.add(id);
        } else {
            targetOf(kind, id).ifPresent(visible::add);
        }
    }

    private static boolean hasGlobalScope(UserEntity user) {
        return Role.of(user.getRole()).map(Role::hasGlobalSecurityScope).orElse(false);
    }

    private static Optional<ScanTarget> targetOf(String kind, Long id) {
        if (TeamRules.KIND_REPOSITORY.equals(kind)) {
            return Optional.of(new ScanTarget.Repository(id));
        }
        if (TeamRules.KIND_CONTAINER.equals(kind)) {
            return Optional.of(new ScanTarget.Container(id));
        }
        return Optional.empty();
    }
}
