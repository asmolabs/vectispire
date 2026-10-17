package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleProject;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.core.ai.AiReviewService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.notifications.NotificationService;
import com.asmolabs.vectispire.core.platform.SettingsAdministrationService;
import com.asmolabs.vectispire.core.settings.persistence.SettingEntity;
import com.asmolabs.vectispire.core.settings.persistence.SettingRepository;
import com.asmolabs.vectispire.core.tickets.TicketService;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetRepository;
import com.asmolabs.vectispire.core.access.persistence.UserTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.UserTargetRepository;
import com.asmolabs.vectispire.core.issues.IssueDecisionService;
import com.asmolabs.vectispire.core.issues.VexIngestorService;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * What the access module answers — the Rust control plane's {@code cp-access} crate reads it as the reference
 * ({@code vectispire-rust/reference/access/}), as the agent's port reads {@code vectispire-common}'s.
 *
 * <p><b>The Java code itself answers, never a restatement of it</b>: {@link Role}'s flags, the markers'
 * {@code @PreAuthorize}, {@link VisibilityMode#of}, {@link VisibilityService} over a matrix of accounts, grants,
 * modes and credential restrictions (its repositories answered from the matrix, as {@code VisibilityServiceTest}
 * answers them), {@link RowVisibility} over a matrix of allowances and projects, and the four-eyes methods of
 * {@code IssueDecisionService} and {@code VexIngestorService}, called through reflection because they are private
 * — a copy of their condition here would test the copy. The one rule this file states rather than calls is the
 * backlog's row rule ({@code IssueSpecifications.visible}, a JPA predicate), marked where it is used.
 *
 * <p>Checked on every build, like the agent's sets: without {@code -Dvectispire.rust.reference.write=true} the
 * test fails when an answer differs from the committed file.
 */
class AccessReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    // ── the role model ────────────────────────────────────────────────────────────────────

    @Test
    void theRolesAndTheirFlags() throws Exception {
        ObjectNode out = JSON.createObjectNode();
        ArrayNode roles = out.putArray("roles");
        for (Role role : Role.values()) {
            ObjectNode row = roles.addObject();
            row.put("name", role.name());
            row.put("administrative", role.isAdministrative());
            row.put("globalSecurityScope", role.hasGlobalSecurityScope());
            row.put("canApproveTriage", role.canApproveTriage());
            row.put("canWriteGovernance", role.canWriteGovernance());
            row.put("canCauseEffects", role.canCauseEffects());
            row.put("governsPlatform", role.governsPlatform());
        }
        ArrayNode parsed = out.putArray("parse");
        for (String input : new String[] {"ADMIN", "admin", " ADMIN", "ADMIN ", "", "ROOT", "SECURITY_CHAMPION", null}) {
            ObjectNode row = parsed.addObject();
            row.put("input", input);
            row.put("role", Role.of(input).map(Enum::name).orElse(null));
        }
        ArrayNode administrative = out.putArray("administrative");
        Role.administrative().forEach(role -> administrative.add(role.name()));
        out.set("approverRoles", names(staticField(TriageApprovers.class, "APPROVER_ROLES")));
        out.set("publisherRoles", names(staticField(TriageApprovers.class, "PUBLISHER_ROLES")));
        expect("access/roles.json", out);
    }

    @Test
    void theMarkers() throws Exception {
        ObjectNode out = JSON.createObjectNode();
        ArrayNode markers = out.putArray("markers");
        for (String name : List.of("OpenToAnonymous", "RequiresAccount", "RequiresAdministrator", "RequiresAgentKey",
                "RequiresGovernanceRead", "RequiresPlatformGovernor", "RequiresSecurityLead", "RequiresWriteAccount")) {
            @SuppressWarnings("unchecked")
            Class<? extends Annotation> marker = (Class<? extends Annotation>)
                    Class.forName("com.asmolabs.vectispire.core.access.web.security." + name);
            PreAuthorize rule = marker.getAnnotation(PreAuthorize.class);
            ObjectNode row = markers.addObject();
            row.put("marker", name);
            row.put("expression", rule == null ? null : rule.value());
        }
        expect("access/markers.json", out);
    }

    @Test
    void theModes() {
        ObjectNode out = JSON.createObjectNode();
        ArrayNode modes = out.putArray("modes");
        for (String input : new String[] {"everyone", "EVERYONE", " everyone ", "assigned", "Assigned ", " everyone",
                "\u0001everyone\u0002", "everyone\t", "everybody", "", null, "ASSİGNED", " assigned"}) {
            ObjectNode row = modes.addObject();
            row.put("input", input);
            row.put("mode", VisibilityMode.of(input).wireName());
        }
        expect("access/modes.json", out);
    }

    @Test
    void theRestrictionAKeyCarries() throws Exception {
        Method restrictionOf = ApiKeyAuthService.class.getDeclaredMethod("restrictionOf", ApiKeyView.class);
        restrictionOf.setAccessible(true);
        ObjectNode out = JSON.createObjectNode();
        ArrayNode keys = out.putArray("keys");
        Object[][] inputs = {{null, null}, {"repository", null}, {null, 5L}, {"repository", 4L}, {"container", 4L},
                {"project", 4L}, {"Repository", 4L}, {"", 4L}};
        for (Object[] input : inputs) {
            ApiKeyView key = new ApiKeyView(UUID.fromString("00000000-0000-0000-0000-000000000001"), "k", "vsk_x",
                    Instant.EPOCH, null, "read", (String) input[0], (Long) input[1], null, 1L);
            ObjectNode row = keys.addObject();
            row.put("targetKind", (String) input[0]);
            if (input[1] == null) {
                row.putNull("targetId");
            } else {
                row.put("targetId", (Long) input[1]);
            }
            row.set("restriction", visibility((Visibility) restrictionOf.invoke(null, key)));
        }
        expect("access/key-restrictions.json", out);
    }

    // ── VisibilityService over a matrix ───────────────────────────────────────────────────

    /** The targets filed in each project, as {@code GrantableTargets.targetsIn} answers. Project 999 does not exist. */
    static final Map<Long, List<ScanTarget>> PROJECTS = new LinkedHashMap<>();

    static {
        PROJECTS.put(10L, List.of(repository(101), repository(102), container(201)));
        PROJECTS.put(20L, List.of(repository(103)));
        PROJECTS.put(30L, List.of());
        PROJECTS.put(40L, List.of(repository(104), container(202), container(203)));
    }

    /** One way of being granted: direct grants, and teams with theirs. */
    record G(String kind, long id) {}

    record Setup(String name, List<G> direct, List<List<G>> teams) {}

    static List<Setup> setups() {
        List<Setup> setups = new ArrayList<>();
        setups.add(new Setup("none", List.of(), List.of()));
        setups.add(new Setup("direct-repository", List.of(grant("repository", 105)), List.of()));
        setups.add(new Setup("direct-container", List.of(grant("container", 204)), List.of()));
        setups.add(new Setup("team-repository", List.of(), List.of(List.of(grant("repository", 106)))));
        setups.add(new Setup("direct-project", List.of(grant("project", 10)), List.of()));
        setups.add(new Setup("team-project-and-overlap", List.of(grant("repository", 101)),
                List.of(List.of(grant("project", 20)))));
        setups.add(new Setup("two-teams", List.of(), List.of(
                List.of(grant("repository", 106), grant("project", 40)),
                List.of(grant("container", 205), grant("repository", 106)))));
        setups.add(new Setup("unknown-kind-and-empty-project", List.of(grant("group", 1), grant("project", 30)),
                List.of()));
        setups.add(new Setup("absent-project-and-empty-team", List.of(grant("project", 999)), List.of(List.of())));
        return setups;
    }

    static final String[] ROLES = {"SUPERUSER", "ADMIN", "CISO", "SECURITY_CHAMPION", "AUDITOR", "USER", "admin"};
    // The settings value as stored; every spelling `VisibilityMode.of` reads is in `modes.json`.
    static final String[] MODES = {"everyone", "assigned", "nonsense"};

    static List<Visibility> restrictions() {
        return List.of(Visibility.everything(), Visibility.only(List.of(repository(101))),
                Visibility.only(List.of(repository(999))), Visibility.only(List.of(container(201))),
                Visibility.only(List.of()));
    }

    /** The backlog the row rule is applied to: every combination of a repository and an image a row can name. */
    static final long[][] ISSUES = {
        {1, 101, 0}, {2, 105, 204}, {3, 0, 201}, {4, 0, 205}, {5, 0, 0}, {6, 106, 0}, {7, 104, 202}, {8, 0, 204},
        {9, 999, 201}, {10, 103, 0}
    };

    @Test
    void theAllowances() {
        ObjectNode out = JSON.createObjectNode();
        ObjectNode projects = out.putObject("projects");
        PROJECTS.forEach((id, targets) -> projects.set(String.valueOf(id), targets(targets)));
        ArrayNode issues = out.putArray("issues");
        for (long[] issue : ISSUES) {
            ObjectNode row = issues.addObject();
            row.put("id", issue[0]);
            if (issue[1] == 0) {
                row.putNull("repoId");
            } else {
                row.put("repoId", issue[1]);
            }
            if (issue[2] == 0) {
                row.putNull("containerId");
            } else {
                row.put("containerId", issue[2]);
            }
        }

        ArrayNode setupsOut = out.putArray("setups");
        ArrayNode cases = out.putArray("cases");
        List<Setup> setups = setups();
        for (int s = 0; s < setups.size(); s++) {
            Setup setup = setups.get(s);
            ObjectNode setupOut = setupsOut.addObject();
            setupOut.put("name", setup.name());
            setupOut.set("direct", grants(setup.direct()));
            ArrayNode teams = setupOut.putArray("teams");
            for (int t = 0; t < setup.teams().size(); t++) {
                ObjectNode team = teams.addObject();
                team.put("id", teamId(s, t));
                team.set("grants", grants(setup.teams().get(t)));
            }
            for (int r = 0; r < ROLES.length; r++) {
                long userId = userId(s, r);
                for (String mode : MODES) {
                    for (Visibility restriction : restrictions()) {
                        VisibilityService service = serviceFor(setup, s, userId, mode);
                        UserView user = user(userId, ROLES[r]);
                        VisibilityService.Allowance allowance = service.allowance(user, restriction);
                        assertThat(service.of(user, restriction)).isEqualTo(allowance.visibility());
                        ObjectNode row = cases.addObject();
                        row.put("setup", setup.name());
                        row.put("userId", userId);
                        row.put("role", ROLES[r]);
                        row.put("mode", mode);
                        row.set("restriction", visibility(restriction));
                        row.set("allowance", allowance(allowance));
                        row.set("visibleIssues", visibleIssues(allowance.visibility()));
                    }
                }
            }
        }
        // No account: nothing, whatever the mode and the restriction.
        for (String mode : MODES) {
            for (Visibility restriction : restrictions()) {
                VisibilityService service = serviceFor(setups.getFirst(), 0, -1, mode);
                ObjectNode row = cases.addObject();
                row.put("setup", "no-account");
                row.putNull("userId");
                row.putNull("role");
                row.put("mode", mode);
                row.set("restriction", visibility(restriction));
                VisibilityService.Allowance allowance = service.allowance(null, restriction);
                row.set("allowance", allowance(allowance));
                row.set("visibleIssues", visibleIssues(allowance.visibility()));
            }
        }
        expect("access/allowances.json", out);
    }

    static long userId(int setup, int role) {
        return 1000L + setup * 10L + role;
    }

    static long teamId(int setup, int team) {
        return 500L + setup * 10L + team;
    }

    private static VisibilityService serviceFor(Setup setup, int index, long userId, String mode) {
        SettingsService settings = mock(SettingsService.class);
        when(settings.get(Setting.TARGET_VISIBILITY)).thenReturn(mode);
        UserTargetRepository assignments = mock(UserTargetRepository.class);
        TeamMemberRepository memberships = mock(TeamMemberRepository.class);
        TeamTargetRepository teamTargets = mock(TeamTargetRepository.class);
        GrantableTargets targets = mock(GrantableTargets.class);

        List<UserTargetEntity> direct = new ArrayList<>();
        setup.direct().forEach(g -> direct.add(new UserTargetEntity(userId, g.kind(), g.id())));
        when(assignments.findByUserId(anyLong())).thenAnswer(call -> call.<Long>getArgument(0) == userId ? direct : List.of());
        List<TeamMemberEntity> members = new ArrayList<>();
        for (int t = 0; t < setup.teams().size(); t++) {
            members.add(new TeamMemberEntity(teamId(index, t), userId));
        }
        when(memberships.findByUserId(anyLong())).thenAnswer(call -> call.<Long>getArgument(0) == userId ? members : List.of());
        when(teamTargets.findByTeamIdIn(anyList())).thenAnswer(call -> {
            List<Long> asked = call.getArgument(0);
            List<TeamTargetEntity> rows = new ArrayList<>();
            for (int t = 0; t < setup.teams().size(); t++) {
                long team = teamId(index, t);
                if (asked.contains(team)) {
                    setup.teams().get(t).forEach(g -> rows.add(new TeamTargetEntity(team, g.kind(), g.id())));
                }
            }
            return rows;
        });
        when(targets.targetsIn(anyCollection())).thenAnswer(call -> {
            Collection<Long> asked = call.getArgument(0);
            List<ScanTarget> filed = new ArrayList<>();
            asked.forEach(project -> filed.addAll(PROJECTS.getOrDefault(project, List.of())));
            return filed;
        });
        return new VisibilityService(settings, assignments, memberships, teamTargets, targets);
    }

    /**
     * The backlog's row rule, <b>stated here rather than called</b>: {@code IssueSpecifications.visible} is a JPA
     * predicate — {@code repo_id in (…) or (repo_id is null and container_id in (…))}, nothing for an empty grant —
     * which needs a database to run. A row naming both is its repository's (0.11.1).
     */
    private static ArrayNode visibleIssues(Visibility visibility) {
        ArrayNode ids = JSON.createArrayNode();
        for (long[] issue : ISSUES) {
            boolean visible = switch (visibility) {
                case Visibility.Everything ignored -> true;
                case Visibility.Only only -> issue[1] != 0
                        ? only.permits(repository(issue[1]))
                        : issue[2] != 0 && only.permits(container(issue[2]));
            };
            if (visible) {
                ids.add(issue[0]);
            }
        }
        return ids;
    }

    // ── RowVisibility over a matrix ───────────────────────────────────────────────────────

    @Test
    void theRowGuards() {
        Map<String, VisibilityService.Allowance> allowances = new LinkedHashMap<>();
        allowances.put("everything", new VisibilityService.Allowance(Visibility.everything(), Set.of(), false));
        allowances.put("two-repositories", new VisibilityService.Allowance(
                Visibility.only(List.of(repository(101), repository(102))), Set.of(), false));
        allowances.put("narrowed-key", new VisibilityService.Allowance(
                Visibility.only(List.of(repository(101))), Set.of(), true));
        allowances.put("project-granted-empty", new VisibilityService.Allowance(Visibility.only(List.of()), Set.of(10L), false));
        allowances.put("repository-image-project", new VisibilityService.Allowance(
                Visibility.only(List.of(repository(103), container(201))), Set.of(20L), false));
        allowances.put("nothing", new VisibilityService.Allowance(Visibility.only(List.of()), Set.of(), false));
        allowances.put("whole-project-10", new VisibilityService.Allowance(
                Visibility.only(List.of(repository(101), repository(102), container(201))), Set.of(), false));

        record Project(long id, String name, List<Long> repositories, List<ScanTarget> filed) {}
        List<Project> projects = List.of(
                new Project(10, "Payments", List.of(101L, 102L), List.of(repository(101), repository(102), container(201))),
                new Project(20, "Ledger", List.of(103L), List.of(repository(103))),
                new Project(30, "Empty", List.of(), List.of()),
                new Project(40, null, List.of(104L), List.of(repository(104), container(202))),
                new Project(50, "Duplicated", List.of(101L), List.of(repository(101), repository(101), container(201))));
        record Solution(long id, String name, List<Long> projects, List<ScanTarget> filed) {}
        List<Solution> solutions = List.of(
                new Solution(1, "Retail", List.of(10L, 20L),
                        List.of(repository(101), repository(102), container(201), repository(103))),
                new Solution(2, null, List.of(10L), List.of(repository(101))),
                new Solution(3, "Other", List.of(30L), List.of()));
        List<ScanTarget> targets = List.of(repository(101), repository(102), container(201), container(202), repository(999));

        ObjectNode out = JSON.createObjectNode();
        ObjectNode allowancesOut = out.putObject("allowances");
        allowances.forEach((name, allowance) -> allowancesOut.set(name, allowance(allowance)));
        ArrayNode projectsOut = out.putArray("projects");
        projects.forEach(p -> {
            ObjectNode row = projectsOut.addObject();
            row.put("id", p.id());
            row.put("name", p.name());
            ArrayNode repositories = row.putArray("repositories");
            p.repositories().forEach(repositories::add);
            row.set("filed", targets(p.filed()));
        });
        ArrayNode solutionsOut = out.putArray("solutions");
        solutions.forEach(s -> {
            ObjectNode row = solutionsOut.addObject();
            row.put("id", s.id());
            row.put("name", s.name());
            ArrayNode ids = row.putArray("projects");
            s.projects().forEach(ids::add);
            row.set("filed", targets(s.filed()));
        });
        out.set("targets", targets(targets));

        ArrayNode cases = out.putArray("cases");
        allowances.forEach((name, allowance) -> {
            Visibility visibility = allowance.visibility();
            for (Project p : projects) {
                ObjectNode row = cases.addObject();
                row.put("allowance", name);
                row.put("project", p.id());
                row.put("seesWholeProject", RowVisibility.seesWholeProject(p.id(), p.repositories(), allowance));
                row.set("whollyVisibleProject", outcome(() -> {
                    VisibleProject project = RowVisibility.requireWhollyVisibleProject(
                            p.id(), Optional.ofNullable(p.name()), p.repositories(), allowance);
                    return JSON.createObjectNode().put("id", project.projectId()).put("name", project.name());
                }));
                row.set("visibleProject", outcome(() -> scope(RowVisibility.requireVisibleProject(
                        p.id(), Optional.ofNullable(p.name()), p.filed(), allowance))));
                row.set("everyTargetOfProject", outcome(() -> scope(RowVisibility.requireEveryTargetOfProject(
                        p.id(), Optional.ofNullable(p.name()), p.repositories(), p.filed(), allowance))));
            }
            for (Solution s : solutions) {
                ObjectNode row = cases.addObject();
                row.put("allowance", name);
                row.put("solution", s.id());
                row.set("visibleSolution", outcome(() -> scope(RowVisibility.requireVisibleSolution(
                        s.id(), Optional.ofNullable(s.name()), s.projects(), s.filed(), allowance))));
            }
            for (ScanTarget target : targets) {
                ObjectNode row = cases.addObject();
                row.put("allowance", name);
                row.set("target", target(target));
                row.set("visible", outcome(() -> target(RowVisibility.requireVisible(target, visibility).target())));
                row.set("rowPresent", outcome(() -> JSON.getNodeFactory().textNode(
                        RowVisibility.requireVisible(Optional.of("row"), target, visibility))));
                row.set("rowAbsent", outcome(() -> JSON.getNodeFactory().textNode(
                        RowVisibility.requireVisible(Optional.<String>empty(), target, visibility))));
                row.set("issue", outcome(() -> JSON.getNodeFactory().textNode(
                        RowVisibility.requireVisibleIssue("row", ignored -> target, visibility))));
                row.set("scan", outcome(() -> JSON.getNodeFactory().textNode(
                        RowVisibility.requireVisibleScan("row", ignored -> target, visibility))));
                if (target instanceof ScanTarget.Repository repository) {
                    row.set("repository", outcome(() -> JSON.getNodeFactory().textNode(
                            RowVisibility.requireVisibleRepository("row", repository.id(), visibility))));
                    row.set("repositoryAbsent", outcome(() -> JSON.getNodeFactory().textNode(
                            RowVisibility.requireVisibleRepository(null, repository.id(), visibility))));
                }
            }
            ObjectNode unclassified = cases.addObject();
            unclassified.put("allowance", name);
            unclassified.putNull("target");
            unclassified.set("issue", outcome(() -> JSON.getNodeFactory().textNode(
                    RowVisibility.requireVisibleIssue("row", ignored -> null, visibility))));
            unclassified.set("scan", outcome(() -> JSON.getNodeFactory().textNode(
                    RowVisibility.requireVisibleScan("row", ignored -> null, visibility))));
            unclassified.set("issueAbsent", outcome(() -> JSON.getNodeFactory().textNode(
                    RowVisibility.requireVisibleIssue((String) null, ignored -> repository(101), visibility))));
            unclassified.set("scanAbsent", outcome(() -> JSON.getNodeFactory().textNode(
                    RowVisibility.requireVisibleScan((String) null, ignored -> repository(101), visibility))));
        });
        expect("access/rows.json", out);
    }

    // ── four-eyes ─────────────────────────────────────────────────────────────────────────

    @Test
    void fourEyes() throws Exception {
        IssueDecisionService byHand = mock(IssueDecisionService.class, Answers.CALLS_REAL_METHODS);
        VexIngestorService byImport = mock(VexIngestorService.class, Answers.CALLS_REAL_METHODS);
        Method handRule = IssueDecisionService.class.getDeclaredMethod("canApprove", IssueDecisionService.Caller.class);
        Method importRule = VexIngestorService.class.getDeclaredMethod("canApprove", IssueDecisionService.Caller.class);
        handRule.setAccessible(true);
        importRule.setAccessible(true);

        ObjectNode out = JSON.createObjectNode();
        ArrayNode cases = out.putArray("cases");
        for (boolean fourEyes : new boolean[] {false, true}) {
            SettingsService settings = mock(SettingsService.class);
            when(settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED)).thenReturn(fourEyes);
            setField(IssueDecisionService.class, byHand, "settings", settings);
            setField(VexIngestorService.class, byImport, "settings", settings);
            List<String> deciders = new ArrayList<>();
            deciders.add(null);
            deciders.addAll(List.of(ROLES));
            deciders.add("");
            for (String role : deciders) {
                Optional<UserView> user = role == null ? Optional.empty() : Optional.of(user(7, role));
                IssueDecisionService.Caller caller =
                        new IssueDecisionService.Caller(user, Visibility.everything(), "127.0.0.1", "test");
                ObjectNode row = cases.addObject();
                row.put("fourEyes", fourEyes);
                row.put("account", role != null);
                row.put("role", role);
                row.put("settlesByHand", (boolean) handRule.invoke(byHand, caller));
                row.put("settlesByImport", (boolean) importRule.invoke(byImport, caller));
            }
        }
        expect("access/four-eyes.json", out);
    }

    /**
     * The four-eyes setting as the rest of the code reads it, and the three refusals that keep it from being switched
     * on where it could not be honoured — {@code SettingsService.isEnabled} over stored spellings, and
     * {@code SettingsAdministrationService.update} itself, called by the platform governor over value spellings and
     * every answer {@link TriageApprovers} could give. The outcome is the refusal's sentence or what the save did
     * otherwise: whatever comes after the four-eyes guards (the type's validation, mostly) is the settings module's.
     */
    @Test
    void theFourEyesSwitch() {
        ObjectNode out = JSON.createObjectNode();
        ArrayNode read = out.putArray("isEnabled");
        List<String> stored = new ArrayList<>();
        stored.add("<absent>");
        stored.add("<null>");
        stored.addAll(List.of("true", "TRUE", " true", "true ", "false", "", "1", "yes"));
        for (String value : stored) {
            SettingRepository repository = mock(SettingRepository.class);
            Optional<SettingEntity> row = Optional.empty();
            if (!value.equals("<absent>")) {
                SettingEntity entity = new SettingEntity();
                entity.setKey(Setting.FOUR_EYES_APPROVAL_REQUIRED.key());
                entity.setValue(value.equals("<null>") ? null : value);
                row = Optional.of(entity);
            }
            when(repository.findById(Setting.FOUR_EYES_APPROVAL_REQUIRED.key())).thenReturn(row);
            ObjectNode line = read.addObject();
            line.put("stored", value);
            line.put("enabled", new SettingsService(repository).isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED));
        }

        ArrayNode switches = out.putArray("switchOn");
        List<String> values = List.of("true", "TRUE", "tRuE", " true\t", "\u0001true", "\u00a0true", "1", " 1 ", "01",
                "false", "0", "yes", "");
        for (String value : values) {
            for (int answers = 0; answers < 8; answers++) {
                boolean anyActive = (answers & 1) != 0;
                boolean twoPublish = (answers & 2) != 0;
                boolean twoSignOff = (answers & 4) != 0;
                SettingsService settings = mock(SettingsService.class);
                when(settings.get(org.mockito.ArgumentMatchers.any(Setting.class)))
                        .thenAnswer(call -> ((Setting) call.getArgument(0)).defaultValue());
                AiReviewService aiReview = mock(AiReviewService.class);
                when(aiReview.openAiUrl()).thenReturn("");
                when(aiReview.ollamaUrl()).thenReturn("");
                TriageApprovers approvers = mock(TriageApprovers.class);
                when(approvers.anyActive()).thenReturn(anyActive);
                when(approvers.twoCanPublishTemplates()).thenReturn(twoPublish);
                when(approvers.twoCanSignOffChecklists()).thenReturn(twoSignOff);
                SettingsAdministrationService service = new SettingsAdministrationService(settings, aiReview, approvers,
                        mock(TicketService.class), mock(NotificationService.class), mock(AuditLogService.class),
                        Clock.systemUTC());
                ObjectNode line = switches.addObject();
                line.put("value", value);
                line.put("anyActive", anyActive);
                line.put("twoCanPublishTemplates", twoPublish);
                line.put("twoCanSignOffChecklists", twoSignOff);
                String outcome;
                try {
                    service.update(Map.of(Setting.FOUR_EYES_APPROVAL_REQUIRED.key(), value),
                            Optional.of(user(1, "SUPERUSER")), new RequestActor("u1", "127.0.0.1", "test"));
                    outcome = "saved";
                } catch (InvalidInputException refused) {
                    outcome = refused.getMessage();
                }
                line.put("outcome", outcome);
            }
        }
        expect("access/four-eyes-switch.json", out);
    }

    // ── helpers ───────────────────────────────────────────────────────────────────────────

    private static G grant(String kind, long id) {
        return new G(kind, id);
    }

    private static ScanTarget repository(long id) {
        return new ScanTarget.Repository(id);
    }

    private static ScanTarget container(long id) {
        return new ScanTarget.Container(id);
    }

    private static UserView user(long id, String role) {
        return new UserView(id, "u" + id, null, null, null, role, true, null, null, Instant.EPOCH, Instant.EPOCH, false,
                false);
    }

    private static ArrayNode grants(List<G> grants) {
        ArrayNode out = JSON.createArrayNode();
        grants.forEach(g -> out.addArray().add(g.kind()).add(g.id()));
        return out;
    }

    private static ObjectNode target(ScanTarget target) {
        ObjectNode out = JSON.createObjectNode();
        switch (target) {
            case ScanTarget.Repository repository -> out.put("repository", repository.id());
            case ScanTarget.Container container -> out.put("container", container.id());
        }
        return out;
    }

    private static ArrayNode targets(Collection<ScanTarget> targets) {
        ArrayNode out = JSON.createArrayNode();
        targets.forEach(target -> out.add(target(target)));
        return out;
    }

    /** Repositories then images, each ascending: the order the Rust side's set iterates in. */
    private static final Comparator<ScanTarget> ORDER = Comparator
            .comparing((ScanTarget target) -> target instanceof ScanTarget.Container)
            .thenComparingLong(target -> switch (target) {
                case ScanTarget.Repository repository -> repository.id();
                case ScanTarget.Container container -> container.id();
            });

    private static com.fasterxml.jackson.databind.JsonNode visibility(Visibility visibility) {
        return switch (visibility) {
            case Visibility.Everything ignored -> JSON.getNodeFactory().textNode("everything");
            case Visibility.Only only -> {
                TreeSet<ScanTarget> sorted = new TreeSet<>(ORDER);
                sorted.addAll(only.targets());
                ObjectNode out = JSON.createObjectNode();
                out.set("only", targets(sorted));
                yield out;
            }
        };
    }

    private static ObjectNode allowance(VisibilityService.Allowance allowance) {
        ObjectNode out = JSON.createObjectNode();
        out.set("visibility", visibility(allowance.visibility()));
        ArrayNode projects = out.putArray("grantedProjects");
        new TreeSet<>(allowance.grantedProjects()).forEach(projects::add);
        out.put("narrowedByCredential", allowance.narrowedByCredential());
        return out;
    }

    private static ObjectNode scope(VisibleScope scope) {
        ObjectNode out = JSON.createObjectNode();
        out.put("kind", scope.kind().name());
        out.put("id", scope.id());
        out.put("name", scope.name());
        out.set("visible", targets(scope.targets()));
        out.put("partial", scope.partial());
        return out;
    }

    /** `{"ok": …}` or `{"notFound": "<sentence>"}` — the one refusal every guard gives. */
    private static ObjectNode outcome(Supplier<com.fasterxml.jackson.databind.JsonNode> guarded) {
        ObjectNode out = JSON.createObjectNode();
        try {
            out.set("ok", guarded.get());
        } catch (NotFoundException refused) {
            out.put("notFound", refused.getMessage());
        }
        return out;
    }

    private static ArrayNode names(Object roles) {
        ArrayNode out = JSON.createArrayNode();
        ((List<?>) roles).forEach(role -> out.add(role.toString()));
        return out;
    }

    private static Object staticField(Class<?> owner, String name) throws ReflectiveOperationException {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(null);
    }

    private static void setField(Class<?> owner, Object target, String name, Object value) throws ReflectiveOperationException {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    /** Writes in write mode, otherwise requires the committed file to say exactly this — `common.rust.ReferenceSet`. */
    private static void expect(String relative, ObjectNode content) {
        String dir = System.getProperty("vectispire.rust.reference");
        assertThat(dir).as("vectispire.rust.reference is set by vectispire-core's test task").isNotBlank();
        Path file = Path.of(dir).resolve(relative);
        String text;
        try {
            text = JSON.writeValueAsString(content) + "\n";
        } catch (IOException unwritable) {
            throw new UncheckedIOException(unwritable);
        }
        if (Boolean.getBoolean("vectispire.rust.reference.write")) {
            try {
                Files.createDirectories(file.getParent());
                Files.writeString(file, text, StandardCharsets.UTF_8);
            } catch (IOException unwritable) {
                throw new UncheckedIOException(unwritable);
            }
            return;
        }
        assertThat(file)
                .as("%s differs from what the Java side answers. Regenerate with ./gradlew :vectispire-core:test --tests "
                        + "'*AccessReferenceSetTest*' -Dvectispire.rust.reference.write=true, then make the Rust port "
                        + "agree (vectispire-rust/check.sh).", relative)
                .exists()
                .content(StandardCharsets.UTF_8)
                .isEqualTo(text);
    }
}
