package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.persistence.TeamTargetEntity;
import com.asmolabs.vectispire.core.persistence.TeamWebhookEntity;
import com.asmolabs.vectispire.core.repositories.TeamMembers;
import com.asmolabs.vectispire.core.repositories.TeamTargets;
import com.asmolabs.vectispire.core.repositories.TeamWebhooks;
import com.asmolabs.vectispire.core.repositories.Teams;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.SettingsService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Managing teams. Administrators only, enforced at the entry point.
 *
 * <p><b>Why teams exist beside per-account assignment.</b> Assignment per account is the right
 * tool for an exception and the wrong one for an organisation: it costs a row per account per
 * target, so onboarding somebody means repeating every pairing by hand, and the day a repository
 * is added, whoever adds it has to remember every account that should see it. A team is that
 * relation factorised — and the audit entry for "added to Backend" says something a list of
 * eleven pairings does not.
 *
 * <p>The two coexist and are <b>unioned</b>, for the reason set out on
 * {@code VisibilityService}: intersecting them would make joining a team narrow what somebody
 * already had.
 */
@RestController
@RequestMapping("/api/v1/teams")
@RequiresAdministrator
public class TeamsController {

    private final Teams teams;
    private final TeamMembers memberships;
    private final TeamTargets targets;
    private final TeamWebhooks webhooks;
    private final Users users;
    private final OutboundUrlGuard outbound;
    private final SettingsService settings;
    private final AuditLogService audit;
    private final Clock clock;

    public TeamsController(
            Teams teams,
            TeamMembers memberships,
            TeamTargets targets,
            TeamWebhooks webhooks,
            Users users,
            OutboundUrlGuard outbound,
            SettingsService settings,
            AuditLogService audit,
            Clock clock) {
        this.teams = teams;
        this.memberships = memberships;
        this.targets = targets;
        this.webhooks = webhooks;
        this.users = users;
        this.outbound = outbound;
        this.settings = settings;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * @param memberCount and {@code targetCount} on the list, so the administration screen can
     *     say "four people, two repositories" without one request per team. A team with no
     *     targets grants nothing, and that is worth seeing at a glance rather than by opening it
     * @param notified whether this team has its own channel — <b>and not the URL</b>. A webhook
     *     URL is a bearer capability: whoever reads it can post in the channel where the team
     *     awaits Vectispire's alerts, which is where a forged message carries most weight. The
     *     settings catalogue makes the same choice for the global one
     */
    public record TeamSummary(
            Long id, String name, String description, int memberCount, int targetCount, boolean notified) {}

    public record TeamRequest(String name, String description) {}

    /**
     * @param url the channel, or empty to remove it. Write-only by construction: there is no route
     *     that returns it, so an account that should not have it cannot read it back out of the
     *     screen that sets it
     */
    public record WebhookRequest(String url) {}

    public record TargetAssignment(String kind, Long id) {}

    @GetMapping
    public List<TeamSummary> list() {
        // Counted in two queries rather than in one per team: the screen shows every team, and a
        // per-team count is where a list endpoint quietly becomes N+1.
        Map<Long, Long> members = countBy(memberships.findAll().stream()
                .map(row -> row.getId().teamId()));
        Map<Long, Long> owned = countBy(targets.findAll().stream()
                .map(row -> row.getId().teamId()));
        java.util.Set<Long> notified = webhooks.findAll().stream()
                .map(TeamWebhookEntity::getTeamId)
                .collect(java.util.stream.Collectors.toSet());

        return teams.findAll().stream()
                .sorted(Comparator.comparing(TeamEntity::getName, String.CASE_INSENSITIVE_ORDER))
                .map(team -> new TeamSummary(
                        team.getId(),
                        team.getName(),
                        team.getDescription(),
                        members.getOrDefault(team.getId(), 0L).intValue(),
                        owned.getOrDefault(team.getId(), 0L).intValue(),
                        notified.contains(team.getId())))
                .toList();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public TeamSummary create(
            @RequestBody TeamRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String name = TeamRules.validateName(body == null ? null : body.name());
        refuseIfNameTaken(name, null);

        TeamEntity team = new TeamEntity();
        team.setName(name);
        team.setDescription(TeamRules.trimDescription(body == null ? null : body.description()));
        team.setCreatedAt(clock.instant());
        TeamEntity saved = teams.save(team);

        record(principal, request, saved.getId(), AuditOperation.TEAM_UPDATED, "Team created: " + name);
        return new TeamSummary(saved.getId(), saved.getName(), saved.getDescription(), 0, 0, false);
    }

    @PatchMapping("/{id}")
    public TeamSummary rename(
            @PathVariable long id,
            @RequestBody TeamRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        TeamEntity team = teams.findById(id).orElseThrow(() -> new NoSuchElementException("Team not found."));
        String previous = team.getName();

        if (body != null && body.name() != null) {
            String name = TeamRules.validateName(body.name());
            refuseIfNameTaken(name, id);
            team.setName(name);
        }
        if (body != null && body.description() != null) {
            team.setDescription(TeamRules.trimDescription(body.description()));
        }
        teams.save(team);

        record(principal, request, id, AuditOperation.TEAM_UPDATED,
                "Team " + previous + " updated" + (previous.equals(team.getName()) ? "" : " → " + team.getName()));
        return new TeamSummary(
                team.getId(),
                team.getName(),
                team.getDescription(),
                memberships.findByTeamId(id).size(),
                targets.findByTeamId(id).size(),
                webhooks.existsById(id));
    }

    /**
     * Deletes a team.
     *
     * <p>Its memberships, its target assignments <b>and its channel</b> go first,
     * <b>explicitly</b>, and that is not belt-and-braces. The schema declares them as cascading
     * foreign keys and SQLite enforces foreign keys only when {@code PRAGMA foreign_keys = ON}
     * has been issued on the connection — which nothing here does. On that engine the cascade is
     * decoration: the team row would disappear and its membership rows would stay, so every
     * member would keep seeing everything the team owned, through rows pointing at a team that no
     * longer exists. Revocation may not depend on which of four engines is underneath.
     *
     * <p><b>The channel was the one that got forgotten</b>, and it was measured on a real SQLite
     * file rather than assumed: deleting the team left the {@code t_team_webhook} row behind. It
     * is not an access-control hole — {@code AUTOINCREMENT} means no later team inherits the
     * identifier, which was checked too — but it is a <em>bearer capability</em> outliving its
     * owner in a table no screen shows and nothing purges. Whoever reads that row can still post
     * in the channel, and the URL survives the rotation its deletion should have forced.
     *
     * <p>That is also the sharpness of the gesture: every member loses, at once, everything the
     * team owned. The audit entry names the counts, because "deleted team Backend" and "deleted
     * team Backend, 11 people, 40 repositories" are not the same sentence to whoever reads the
     * log afterwards.
     */
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        TeamEntity team = teams.findById(id).orElseThrow(() -> new NoSuchElementException("Team not found."));
        int members = memberships.findByTeamId(id).size();
        int owned = targets.findByTeamId(id).size();

        memberships.deleteByTeamId(id);
        targets.deleteByTeamId(id);
        webhooks.deleteById(id);
        teams.deleteById(id);
        record(principal, request, id, AuditOperation.TEAM_UPDATED,
                "Team deleted: " + team.getName() + " (" + members + " member(s), " + owned + " target(s))");
    }

    @GetMapping("/{id}/members")
    public List<Long> members(@PathVariable long id) {
        requireTeam(id);
        return memberships.findByTeamId(id).stream().map(row -> row.getId().userId()).toList();
    }

    /**
     * Replaces the membership wholesale.
     *
     * <p>Wholesale rather than add-and-remove, as everywhere else here: the operation that
     * matters is <em>removing</em> somebody, and a screen that sends what it wants against a
     * server that only adds is a revocation that silently does nothing.
     */
    @PutMapping("/{id}/members")
    public List<Long> setMembers(
            @PathVariable long id,
            @RequestBody List<Long> body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        TeamEntity team = requireTeam(id);
        List<Long> wanted = body == null ? List.of() : body.stream().filter(java.util.Objects::nonNull).distinct().toList();

        // Refused rather than skipped. A screen sending an identifier that no longer exists is
        // out of date, and silently dropping it makes the result differ from what was sent
        // without anybody being told.
        List<Long> unknown = wanted.stream().filter(userId -> users.findById(userId).isEmpty()).toList();
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException("No such account(s): " + unknown);
        }

        memberships.deleteByTeamId(id);
        wanted.forEach(userId -> memberships.save(new TeamMemberEntity(id, userId)));

        record(principal, request, id, AuditOperation.TEAM_ACCESS_CHANGED,
                "Members of " + team.getName() + ": " + wanted.size());
        return wanted;
    }

    @GetMapping("/{id}/targets")
    public List<TargetAssignment> targets(@PathVariable long id) {
        requireTeam(id);
        return targets.findByTeamId(id).stream()
                .map(row -> new TargetAssignment(row.getId().targetKind(), row.getId().targetId()))
                .toList();
    }

    @PutMapping("/{id}/targets")
    public List<TargetAssignment> setTargets(
            @PathVariable long id,
            @RequestBody List<TargetAssignment> body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        TeamEntity team = requireTeam(id);
        List<TargetAssignment> wanted = new ArrayList<>();
        for (TargetAssignment assignment : body == null ? List.<TargetAssignment>of() : body) {
            if (assignment == null || assignment.id() == null) {
                continue;
            }
            // The kind is validated against the two that exist. An unrecognised kind stored here
            // would resolve to nothing forever — an assignment the screen shows and that grants
            // nothing, which is the most confusing possible outcome.
            wanted.add(new TargetAssignment(TeamRules.validateTargetKind(assignment.kind()), assignment.id()));
        }

        targets.deleteByTeamId(id);
        wanted.forEach(assignment -> targets.save(
                new TeamTargetEntity(id, assignment.kind(), assignment.id())));

        record(principal, request, id, AuditOperation.TEAM_ACCESS_CHANGED,
                "Targets of " + team.getName() + ": " + wanted.size());
        return wanted;
    }

    /**
     * Sets or clears this team's channel.
     *
     * <p><b>Validated here rather than only at send time</b>, though it is validated there too:
     * refusing a private address at the moment it is typed tells the administrator what is wrong
     * while they are still looking at the field, and the check at send time is what stops a value
     * written straight into the database from becoming an unchecked destination. Two checks, one
     * rule — {@code OutboundUrlGuard} owns it.
     *
     * <p>Empty removes the channel: the team then falls back to the global webhook, which is the
     * state it was in before anybody set one.
     */
    @PutMapping("/{id}/webhook")
    public TeamSummary setWebhook(
            @PathVariable long id,
            @RequestBody WebhookRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        TeamEntity team = requireTeam(id);
        String url = body == null || body.url() == null ? "" : body.url().trim();

        if (url.isEmpty()) {
            webhooks.deleteById(id);
            record(principal, request, id, AuditOperation.TEAM_ACCESS_CHANGED,
                    "Webhook removed from " + team.getName());
        } else {
            outbound.validate(url, policy(), "team webhook URL");
            webhooks.save(new TeamWebhookEntity(id, url));
            // **The URL is not in the entry.** An audit log is read by people who are not
            // necessarily allowed to post in that channel, and a capability copied into a table
            // that is deliberately never purged is a capability that outlives its rotation.
            record(principal, request, id, AuditOperation.TEAM_ACCESS_CHANGED,
                    "Webhook set on " + team.getName());
        }

        return new TeamSummary(
                team.getId(),
                team.getName(),
                team.getDescription(),
                memberships.findByTeamId(id).size(),
                targets.findByTeamId(id).size(),
                !url.isEmpty());
    }

    /** The same rule as the global webhook: private destinations only when the operator said so. */
    private OutboundPolicy policy() {
        return settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)
                ? OutboundPolicy.INTERNAL_ALLOWED
                : OutboundPolicy.PUBLIC_ONLY;
    }

    private TeamEntity requireTeam(long id) {
        return teams.findById(id).orElseThrow(() -> new NoSuchElementException("Team not found."));
    }

    private void refuseIfNameTaken(String name, Long allowed) {
        Optional<TeamEntity> existing = teams.findByNameIgnoreCase(name);
        if (existing.isPresent() && !existing.get().getId().equals(allowed)) {
            // Caught here rather than left to the unique constraint: a constraint violation
            // surfaces as a 500 with a driver's message in it, and the administrator needs to
            // read "that name is taken".
            throw new IllegalArgumentException("A team named \"" + name + "\" already exists.");
        }
    }

    private static Map<Long, Long> countBy(java.util.stream.Stream<Long> ids) {
        return ids.collect(java.util.stream.Collectors.groupingBy(id -> id, java.util.stream.Collectors.counting()));
    }

    private void record(
            VectispirePrincipal principal,
            HttpServletRequest request,
            long teamId,
            AuditOperation operation,
            String description) {

        audit.record(new AuditLogService.Record(
                operation,
                String.valueOf(teamId),
                description,
                principal == null ? null : principal.getName(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));
    }
}
