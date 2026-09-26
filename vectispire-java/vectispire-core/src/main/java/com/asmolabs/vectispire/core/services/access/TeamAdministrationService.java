package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.persistence.TeamTargetEntity;
import com.asmolabs.vectispire.core.persistence.TeamWebhookEntity;
import com.asmolabs.vectispire.core.repositories.TeamMembers;
import com.asmolabs.vectispire.core.repositories.TeamTargets;
import com.asmolabs.vectispire.core.repositories.TeamWebhooks;
import com.asmolabs.vectispire.core.repositories.Teams;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.audit.RequestActor;
import com.asmolabs.vectispire.core.services.settings.SettingsService;
import com.asmolabs.vectispire.core.services.shared.TargetNaming;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.stereotype.Service;

/**
 * Teams: who is in one, what it owns, and where its alerts go.
 *
 * <p><b>Why teams exist beside per-account assignment.</b> Assignment per account is the right
 * tool for an exception and the wrong one for an organisation: it costs a row per account per
 * target, so onboarding somebody means repeating every pairing by hand, and the day a repository
 * is added, whoever adds it has to remember every account that should see it. A team is that
 * relation factorised — and the audit entry for "added to Backend" says something a list of
 * eleven pairings does not.
 *
 * <p>The two coexist and are <b>unioned</b>, for the reason set out on
 * {@link VisibilityService}: intersecting them would make joining a team narrow what somebody
 * already had.
 *
 * <p>Every refusal is an {@link IllegalArgumentException} carrying text meant for the screen, and
 * a missing team a {@link NoSuchElementException} — the 400 and the 404 the handler maps.
 */
@Service
public class TeamAdministrationService {

    /** The width of {@code t_team_webhook.url}. */
    private static final int MAX_WEBHOOK_URL_LENGTH = 500;

    private final Teams teams;
    private final TeamMembers memberships;
    private final TeamTargets targets;
    private final TeamWebhooks webhooks;
    private final Users users;
    private final OutboundUrlGuard outbound;
    private final SettingsService settings;
    private final AuditLogService audit;
    private final Clock clock;
    private final GrantTargets grantTargets;
    private final TargetNaming naming;

    public TeamAdministrationService(
            Teams teams,
            TeamMembers memberships,
            TeamTargets targets,
            TeamWebhooks webhooks,
            Users users,
            OutboundUrlGuard outbound,
            SettingsService settings,
            AuditLogService audit,
            Clock clock,
            GrantTargets grantTargets,
            TargetNaming naming) {
        this.teams = teams;
        this.memberships = memberships;
        this.targets = targets;
        this.webhooks = webhooks;
        this.users = users;
        this.outbound = outbound;
        this.settings = settings;
        this.audit = audit;
        this.clock = clock;
        this.grantTargets = grantTargets;
        this.naming = naming;
    }

    /**
     * A team with what the list shows of it.
     *
     * @param notified whether it has its own channel — never the URL, which is a bearer
     *     capability and has no way out of this class
     */
    public record TeamView(TeamEntity team, int memberCount, int targetCount, boolean notified) {}

    /** @param kind {@code repository}, {@code container} or {@code project} */
    public record TargetAssignment(String kind, Long id) implements TargetNaming.Grant {}

    public List<TeamView> list() {
        // Counted in two queries rather than in one per team: the screen shows every team, and a
        // per-team count is where a list endpoint quietly becomes N+1.
        Map<Long, Long> members = countBy(memberships.findAll().stream()
                .map(row -> row.getId().teamId()));
        Map<Long, Long> owned = countBy(targets.findAll().stream()
                .map(row -> row.getId().teamId()));
        Set<Long> notified = webhooks.findAll().stream()
                .map(TeamWebhookEntity::getTeamId)
                .collect(Collectors.toSet());

        return teams.findAll().stream()
                .sorted(Comparator.comparing(TeamEntity::getName, String.CASE_INSENSITIVE_ORDER))
                .map(team -> new TeamView(
                        team,
                        members.getOrDefault(team.getId(), 0L).intValue(),
                        owned.getOrDefault(team.getId(), 0L).intValue(),
                        notified.contains(team.getId())))
                .toList();
    }

    public TeamView create(String requestedName, String description, RequestActor actor) {
        String name = TeamRules.validateName(requestedName);
        refuseIfNameTaken(name, null);

        TeamEntity team = new TeamEntity();
        team.setName(name);
        team.setDescription(TeamRules.trimDescription(description));
        team.setCreatedAt(clock.instant());
        TeamEntity saved = teams.save(team);

        record(actor, saved.getId(), AuditOperation.TEAM_UPDATED, "Team created: " + name);
        return new TeamView(saved, 0, 0, false);
    }

    /** Either field may be null, which leaves it as it is. */
    public TeamView rename(long id, String requestedName, String description, RequestActor actor) {
        TeamEntity team = requireTeam(id);
        String previous = team.getName();

        if (requestedName != null) {
            String name = TeamRules.validateName(requestedName);
            refuseIfNameTaken(name, id);
            team.setName(name);
        }
        if (description != null) {
            team.setDescription(TeamRules.trimDescription(description));
        }
        teams.save(team);

        record(actor, id, AuditOperation.TEAM_UPDATED,
                "Team " + previous + " updated" + (previous.equals(team.getName()) ? "" : " → " + team.getName()));
        return new TeamView(
                team,
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
     * longer exists. Revocation may not depend on which engine is underneath.
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
    public void delete(long id, RequestActor actor) {
        TeamEntity team = requireTeam(id);
        int members = memberships.findByTeamId(id).size();
        int owned = targets.findByTeamId(id).size();

        memberships.deleteByTeamId(id);
        targets.deleteByTeamId(id);
        webhooks.deleteById(id);
        teams.deleteById(id);
        record(actor, id, AuditOperation.TEAM_UPDATED,
                "Team deleted: " + team.getName() + " (" + members + " member(s), " + owned + " target(s))");
    }

    public List<Long> members(long id) {
        requireTeam(id);
        return memberships.findByTeamId(id).stream().map(row -> row.getId().userId()).toList();
    }

    /**
     * Replaces the membership wholesale.
     *
     * <p>Wholesale rather than add-and-remove, as everywhere else here: the operation that
     * matters is <em>removing</em> somebody, and a screen that sends what it wants against a
     * server that only adds is a revocation that silently does nothing.
     *
     * @param requested as sent; nulls and repeats are dropped
     * @return the membership as stored
     */
    public List<Long> replaceMembers(long id, List<Long> requested, RequestActor actor) {
        TeamEntity team = requireTeam(id);
        List<Long> wanted = requested.stream().filter(Objects::nonNull).distinct().toList();

        // Refused rather than skipped. A screen sending an identifier that no longer exists is
        // out of date, and silently dropping it makes the result differ from what was sent
        // without anybody being told.
        List<Long> unknown = wanted.stream().filter(userId -> users.findById(userId).isEmpty()).toList();
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException("No such account(s): " + unknown);
        }

        memberships.deleteByTeamId(id);
        wanted.forEach(userId -> memberships.save(new TeamMemberEntity(id, userId)));

        record(actor, id, AuditOperation.TEAM_ACCESS_CHANGED,
                "Members of " + team.getName() + ": " + wanted.size());
        return wanted;
    }

    /** What the team owns, each target named — a project grant included, which no selector lists. */
    public List<TargetNaming.TargetGrant> targets(long id) {
        requireTeam(id);
        return naming.named(targets.findByTeamId(id).stream()
                .map(row -> new TargetAssignment(row.getId().targetKind(), row.getId().targetId()))
                .toList());
    }

    /**
     * Replaces the targets wholesale.
     *
     * @param requested as sent; a null entry, or one with no id, is skipped
     * @return the assignments as stored, named
     */
    public List<TargetNaming.TargetGrant> replaceTargets(
            long id, List<TargetAssignment> requested, RequestActor actor) {
        TeamEntity team = requireTeam(id);
        List<TargetAssignment> wanted = new ArrayList<>();
        for (TargetAssignment assignment : requested) {
            if (assignment == null || assignment.id() == null) {
                continue;
            }
            // The kind is validated against those that exist, and a project against the table. An
            // unrecognised kind stored here would resolve to nothing forever — an assignment the
            // screen shows and that grants nothing, which is the most confusing possible outcome.
            wanted.add(new TargetAssignment(grantTargets.validate(assignment.kind(), assignment.id()), assignment.id()));
        }

        targets.deleteByTeamId(id);
        wanted.forEach(assignment -> targets.save(
                new TeamTargetEntity(id, assignment.kind(), assignment.id())));

        record(actor, id, AuditOperation.TEAM_ACCESS_CHANGED,
                "Targets of " + team.getName() + ": " + wanted.size());
        return naming.named(wanted);
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
     *
     * @param requestedUrl as sent, possibly null
     */
    public TeamView setWebhook(long id, String requestedUrl, RequestActor actor) {
        TeamEntity team = requireTeam(id);
        String url = requestedUrl == null ? "" : requestedUrl.trim();

        if (url.isEmpty()) {
            webhooks.deleteById(id);
            record(actor, id, AuditOperation.TEAM_ACCESS_CHANGED,
                    "Webhook removed from " + team.getName());
        } else {
            // Before the guard, which resolves the host: a URL the column cannot hold is refused
            // without a DNS lookup, and without the 500 the insert used to answer.
            BoundedText.within(url, MAX_WEBHOOK_URL_LENGTH, "The webhook URL");
            outbound.validate(url, policy(), "team webhook URL");
            webhooks.save(new TeamWebhookEntity(id, url));
            // **The URL is not in the entry.** An audit log is read by people who are not
            // necessarily allowed to post in that channel, and a capability copied into a table
            // that is deliberately never purged is a capability that outlives its rotation.
            record(actor, id, AuditOperation.TEAM_ACCESS_CHANGED,
                    "Webhook set on " + team.getName());
        }

        return new TeamView(
                team,
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

    private static Map<Long, Long> countBy(Stream<Long> ids) {
        return ids.collect(Collectors.groupingBy(id -> id, Collectors.counting()));
    }

    private void record(RequestActor actor, long teamId, AuditOperation operation, String description) {
        audit.record(new AuditLogService.Record(
                operation,
                String.valueOf(teamId),
                description,
                actor.username(),
                actor.ipAddress(),
                actor.userAgent()));
    }
}
