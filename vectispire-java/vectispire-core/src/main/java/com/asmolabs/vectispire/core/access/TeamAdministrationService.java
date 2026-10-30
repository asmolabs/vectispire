package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.notifications.NotificationChannelKind;
import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.access.internal.GrantTargets;
import com.asmolabs.vectispire.core.access.persistence.TeamEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamWebhookEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamWebhookRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

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
 * <p>Every refusal is an {@link InvalidInputException} carrying text meant for the screen, and
 * a missing team a {@link NotFoundException} — the 400 and the 404 the handler maps.
 */
@Service
public class TeamAdministrationService {

    /** The width of {@code t_team_webhook.url}. */
    private static final int MAX_WEBHOOK_URL_LENGTH = 500;

    private final TeamRepository teams;
    private final TeamMemberRepository memberships;
    private final TeamTargetRepository targets;
    private final TeamWebhookRepository webhooks;
    private final UserRepository users;
    private final OutboundUrlGuard outbound;
    private final SettingsService settings;
    private final AuditLogService audit;
    private final Clock clock;
    private final GrantTargets grantTargets;
    private final GrantableTargets grantable;

    /**
     * One transaction per replacement or deletion, the audit entry after it. Each repository call
     * used to commit alone: a failure between the delete and the inserts left a team with none of
     * its members or targets, or a deleted team's rows half gone — the state
     * {@code AccountAdminService.replaceTargets} exists to prevent for an account.
     */
    private final TransactionTemplate transactions;
    private final Integrations integrations;

    public TeamAdministrationService(
            TeamRepository teams,
            TeamMemberRepository memberships,
            TeamTargetRepository targets,
            TeamWebhookRepository webhooks,
            UserRepository users,
            OutboundUrlGuard outbound,
            SettingsService settings,
            AuditLogService audit,
            Clock clock,
            GrantTargets grantTargets,
            GrantableTargets grantable,
            TransactionTemplate transactions,
            Integrations integrations) {
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
        this.grantable = grantable;
        this.transactions = transactions;
        this.integrations = integrations;
    }

    /**
     * A team with what the list shows of it: the row's properties under their own names, and the
     * counts beside them — never the row, which is not the controller's to hold.
     *
     * @param notified whether it has its own channel — never the URL, which is a bearer
     *     capability and has no way out of this class
     */
    public record TeamView(
            Long id,
            String name,
            String description,
            Instant createdAt,
            int memberCount,
            int targetCount,
            boolean notified) {

        static TeamView of(TeamEntity team, int memberCount, int targetCount, boolean notified) {
            return new TeamView(
                    team.getId(), team.getName(), team.getDescription(), team.getCreatedAt(),
                    memberCount, targetCount, notified);
        }
    }

    /** @param kind {@code repository}, {@code container} or {@code project} */
    public record TargetAssignment(String kind, Long id) implements GrantableTargets.Grant {

        /** By kind, then id: the primary key's order after the owner's column. */
        static final Comparator<TargetAssignment> ORDER =
                Comparator.comparing(TargetAssignment::kind).thenComparing(TargetAssignment::id);
    }

    /**
     * The teams by name, all of them or one page. A name is unique whatever its casing, so the order is one a
     * page can be cut from; the identifier settles what the rule would let through.
     *
     * @param limit rows per page, or null for every team ({@link ListWindow#requested})
     * @throws com.asmolabs.vectispire.common.domain.errors.InvalidInputException a window the rule refuses
     */
    public List<TeamView> list(Integer limit, Integer offset) {
        Optional<ListWindow> window = ListWindow.requested(limit, offset);
        // Counted in two queries rather than in one per team: the screen shows every team, and a
        // per-team count is where a list endpoint quietly becomes N+1.
        Map<Long, Long> members = countBy(memberships.findAll().stream()
                .map(row -> row.getId().teamId()));
        Map<Long, Long> owned = countBy(targets.findAll().stream()
                .map(row -> row.getId().teamId()));
        Set<Long> notified = webhooks.findAll().stream()
                .map(TeamWebhookEntity::getTeamId)
                .collect(Collectors.toSet());

        List<TeamEntity> ordered = teams.findAll().stream()
                .sorted(Comparator.comparing(TeamEntity::getName, String.CASE_INSENSITIVE_ORDER)
                        .thenComparing(TeamEntity::getId))
                .toList();
        return window.map(page -> page.of(ordered)).orElse(ordered).stream()
                .map(team -> TeamView.of(
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
        return TeamView.of(saved, 0, 0, false);
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
        return TeamView.of(
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
     * foreign keys, and a cascade an engine does not honour is decoration — MySQL's declared inline
     * before V19, SQLite's without its per-connection pragma. The team row would disappear and its
     * membership rows would stay, so every member would keep seeing everything the team owned,
     * through rows pointing at a team that no longer exists. Revocation may not depend on which
     * engine is underneath, nor on a migration nobody has re-read.
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

        transactions.executeWithoutResult(status -> {
            memberships.deleteByTeamId(id);
            targets.deleteByTeamId(id);
            webhooks.deleteById(id);
            teams.deleteById(id);
        });
        record(actor, id, AuditOperation.TEAM_UPDATED,
                "Team deleted: " + team.getName() + " (" + members + " member(s), " + owned + " target(s))");
    }

    /**
     * The team's members by account id, all of them or one page.
     *
     * <p>Sorted here rather than left to the table: the pages of a list are that list cut, which needs an order
     * every engine agrees on. It is the primary key's, which MySQL answered before paging existed.
     *
     * @param limit rows per page, or null for every member ({@link ListWindow#requested})
     * @throws InvalidInputException a window the rule refuses — after the team's 404
     */
    public List<Long> members(long id, Integer limit, Integer offset) {
        requireTeam(id);
        Optional<ListWindow> window = ListWindow.requested(limit, offset);
        List<Long> every = memberships.findByTeamId(id).stream().map(row -> row.getId().userId()).sorted().toList();
        return window.map(page -> page.of(every)).orElse(every);
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
            throw new InvalidInputException("No such account(s): " + unknown);
        }

        transactions.executeWithoutResult(status -> {
            memberships.deleteByTeamId(id);
            wanted.forEach(userId -> memberships.save(new TeamMemberEntity(id, userId)));
        });

        record(actor, id, AuditOperation.TEAM_ACCESS_CHANGED,
                "Members of " + team.getName() + ": " + wanted.size());
        return wanted;
    }

    /**
     * What the team owns, each target named — a project grant included, which no selector lists.
     *
     * <p>By kind, then id — the primary key's order, made explicit for the same reason as {@link #members}'s — all
     * of them or one page, named for the page's rows only.
     *
     * @param limit rows per page, or null for every target ({@link ListWindow#requested})
     * @throws InvalidInputException a window the rule refuses — after the team's 404
     */
    public List<GrantableTargets.TargetGrant> targets(long id, Integer limit, Integer offset) {
        requireTeam(id);
        Optional<ListWindow> window = ListWindow.requested(limit, offset);
        List<TargetAssignment> every = targets.findByTeamId(id).stream()
                .map(row -> new TargetAssignment(row.getId().targetKind(), row.getId().targetId()))
                .sorted(TargetAssignment.ORDER)
                .toList();
        return grantable.named(window.map(page -> page.of(every)).orElse(every));
    }

    /**
     * Replaces the targets wholesale.
     *
     * @param requested as sent; a null entry, or one with no id, is skipped
     * @param granter what the administrator granting may see: a new grant outside it, or naming a
     *     target that does not exist, is refused as absent ({@link GrantTargets})
     * @return the assignments as stored, named
     */
    public List<GrantableTargets.TargetGrant> replaceTargets(
            long id, List<TargetAssignment> requested, Visibility granter, RequestActor actor) {
        TeamEntity team = requireTeam(id);
        java.util.Set<TargetAssignment> held = targets.findByTeamId(id).stream()
                .map(row -> new TargetAssignment(row.getId().targetKind(), row.getId().targetId()))
                .collect(java.util.stream.Collectors.toSet());
        // A set, as for an account's grants: the pair is the table's primary key, and the same
        // target sent twice was answered and audited as two grants while one row was stored.
        java.util.LinkedHashSet<TargetAssignment> unique = new java.util.LinkedHashSet<>();
        for (TargetAssignment assignment : requested) {
            if (assignment == null || assignment.id() == null) {
                continue;
            }
            // The kind is validated against those that exist, and the target against the tables and
            // the granter's visibility. An unrecognised kind stored here would resolve to nothing
            // forever — an assignment the screen shows and that grants nothing, which is the most
            // confusing possible outcome.
            String kind = grantTargets.validate(assignment.kind(), assignment.id(), granter,
                    (normalized, targetId) -> held.contains(new TargetAssignment(normalized, targetId)));
            unique.add(new TargetAssignment(kind, assignment.id()));
        }
        List<TargetAssignment> wanted = List.copyOf(unique);

        transactions.executeWithoutResult(status -> {
            targets.deleteByTeamId(id);
            wanted.forEach(assignment -> targets.save(
                    new TeamTargetEntity(id, assignment.kind(), assignment.id())));
        });

        record(actor, id, AuditOperation.TEAM_ACCESS_CHANGED,
                "Targets of " + team.getName() + ": " + wanted.size());
        return grantable.named(wanted);
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
     * @throws com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException setting one while
     *     {@code notification.webhook} is disabled; removing one is always accepted
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
            // **A team's webhook is the webhook channel** (decision 0040, lot I6): refused while
            // `notification.webhook` is off, before the guard resolves anything — and held in the write's
            // transaction, so a governor's switch arriving meanwhile waits for it and reads it as in use.
            Integration channel = Integration.of(NotificationChannelKind.WEBHOOK);
            integrations.requireEnabled(channel);
            BoundedText.within(url, MAX_WEBHOOK_URL_LENGTH, "The webhook URL");
            outbound.validate(url, policy(), "team webhook URL");
            transactions.executeWithoutResult(status -> {
                integrations.holdEnabled(channel);
                webhooks.save(new TeamWebhookEntity(id, url));
            });
            // **The URL is not in the entry.** An audit log is read by people who are not
            // necessarily allowed to post in that channel, and a capability copied into a table
            // that is deliberately never purged is a capability that outlives its rotation.
            record(actor, id, AuditOperation.TEAM_ACCESS_CHANGED,
                    "Webhook set on " + team.getName());
        }

        return TeamView.of(
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
        return teams.findById(id).orElseThrow(() -> new NotFoundException("Team not found."));
    }

    private void refuseIfNameTaken(String name, Long allowed) {
        Optional<TeamEntity> existing = teams.findByNameIgnoreCase(name);
        if (existing.isPresent() && !existing.get().getId().equals(allowed)) {
            // Caught here rather than left to the unique constraint: a constraint violation
            // surfaces as a 500 with a driver's message in it, and the administrator needs to
            // read "that name is taken".
            throw new InvalidInputException("A team named \"" + name + "\" already exists.");
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
