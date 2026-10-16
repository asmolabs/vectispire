package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistReminder;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistReminder.Gap;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistReminder.ProfileLines;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistReminder.Unreached;
import com.asmolabs.vectispire.common.domain.checklists.ContactProfiles;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.AccountDirectory;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.audit.AuditLogQueryService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistContactEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistContactRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistRepository;
import com.asmolabs.vectispire.core.notifications.MailNotificationChannel;
import com.asmolabs.vectispire.core.settings.ExportProperties;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import java.time.Clock;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * The weekly reminder of the checklist lines still to fill in (decision 0044), offered every hour by the
 * maintenance tick and sent once a week to each recipient.
 *
 * <h2>Who is written to</h2>
 *
 * <ul>
 *   <li><b>Each account a project linked to a profile</b>, at its own address: one message for all its
 *       projects and profiles, naming each line of a draft that has no answer or a carried one waiting for
 *       confirmation. A submitted revision is not reminded of — nobody can answer it until it is returned.
 *   <li><b>The CISOs</b>, each at their address, when a profile has such lines and reminds nobody: no
 *       account linked, or one gone, deactivated, unable to fill the checklist in, or without an address.
 *       Each CISO is told only of the projects their own account sees whole: a message is not a way round
 *       the 404 a route would have answered.
 * </ul>
 *
 * <h2>Once a week, by the audit log</h2>
 *
 * <p>Like the posture report, the bookkeeping is the entry the sending writes, {@code
 * CHECKLIST_REMINDER_SENT} — but one per recipient, its resource the week's Monday and the recipient, so
 * that a relay refusing one address is retried next hour for that address alone. Written after the send:
 * a crash between the two sends one message twice, rather than a week of silence. Two instances of the
 * control plane may both send in the same hour, as the posture report may; a duplicate is the price of
 * needing no lock. The mark goes through {@code AuditLogService.append}, which throws, and a mark refused
 * stops the run: an audit log refusing writes would otherwise have every recipient written to every hour.
 *
 * <p><b>Never throws</b>, for the tick's sake, and a recipient whose send fails does not stop the others.
 */
@Service
public class ChecklistReminderService {

    private static final Logger log = LoggerFactory.getLogger(ChecklistReminderService.class);

    private final ChecklistRepository checklists;
    private final ChecklistItemRepository items;
    private final ChecklistContactRepository contacts;
    private final ChecklistContactService contactRules;
    private final SolutionQueryService projects;
    private final VisibilityService visibility;
    private final AccountDirectory accounts;
    private final SettingsService settings;
    private final MailNotificationChannel mail;
    private final ExportProperties deployment;
    private final AuditLogQueryService auditLog;
    private final AuditLogService audit;
    private final Clock clock;

    public ChecklistReminderService(
            ChecklistRepository checklists,
            ChecklistItemRepository items,
            ChecklistContactRepository contacts,
            ChecklistContactService contactRules,
            SolutionQueryService projects,
            VisibilityService visibility,
            AccountDirectory accounts,
            SettingsService settings,
            MailNotificationChannel mail,
            ExportProperties deployment,
            AuditLogQueryService auditLog,
            AuditLogService audit,
            Clock clock) {
        this.checklists = checklists;
        this.items = items;
        this.contacts = contacts;
        this.contactRules = contactRules;
        this.projects = projects;
        this.visibility = visibility;
        this.accounts = accounts;
        this.settings = settings;
        this.mail = mail;
        this.deployment = deployment;
        this.auditLog = auditLog;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * Sends this week's reminders not sent yet.
     *
     * @return how many messages left
     */
    public int runOnce() {
        try {
            return send();
        } catch (RuntimeException failed) {
            log.warn("The weekly checklist reminders could not be prepared; they will be tried again next tick.", failed);
            return 0;
        }
    }

    private int send() {
        if (!settings.isEnabled(Setting.CHECKLIST_REMINDERS_ENABLED)) {
            return 0;
        }
        if (!mail.hasRelay()) {
            // Switched on with no relay: the settings screen says the relay is missing; retrying every hour
            // for a week would only fill the log.
            return 0;
        }
        LocalDate weekStarting = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC)
                .with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
        Due due = due();
        Optional<String> publicUrl = deployment.publicUrl();

        Map<String, Pending> sends = new LinkedHashMap<>();
        due.byAccount().forEach((accountId, profiles) -> {
            UserView account = due.accounts().get(accountId);
            ChecklistReminder.Message message = ChecklistReminder.toContact(
                    ChecklistContactService.nameOf(account), profiles, weekStarting, publicUrl);
            int lines = profiles.stream().mapToInt(profile -> profile.lines().size()).sum();
            sends.put(weekStarting + "/contact/" + accountId, new Pending(account.email().strip(), message,
                    "Weekly checklist reminder sent to account " + accountId + ": " + lines + " line(s) on "
                            + profiles.size() + " profile(s)."));
        });
        if (!due.unreached().isEmpty()) {
            List<UserView> cisos = accounts.active().stream()
                    .filter(account -> Role.of(account.role()).filter(role -> role == Role.CISO).isPresent())
                    .filter(account -> account.email() != null && !account.email().isBlank())
                    .toList();
            for (UserView ciso : cisos) {
                VisibilityService.Allowance allowance = visibility.allowance(ciso, Visibility.everything());
                List<Unreached> theirs = due.unreached().stream()
                        .filter(gap -> RowVisibility.seesWholeProject(gap.projectId(),
                                due.repositoryIds().get(gap.projectId()), allowance))
                        .toList();
                if (theirs.isEmpty()) {
                    continue;
                }
                ChecklistReminder.Message message = ChecklistReminder.toCiso(theirs, weekStarting, publicUrl);
                sends.put(weekStarting + "/ciso/" + ciso.id(), new Pending(ciso.email().strip(), message,
                        "Weekly checklist reminder sent to CISO account " + ciso.id() + ": " + theirs.size()
                                + " profile(s) without a contact."));
            }
            if (cisos.isEmpty()) {
                log.info("{} checklist profile(s) have lines to fill in and nobody to remind, and no active CISO "
                        + "account has an e-mail address to be told.", due.unreached().size());
            }
        }

        // Last week's sends the log refused to mark are of no use this week: the keys name their Monday.
        String thisWeek = weekStarting + "/";
        sentUnmarked.removeIf(key -> !key.startsWith(thisWeek));
        Set<String> alreadySent = sends.isEmpty() ? Set.of()
                : auditLog.resourcesNamed(AuditOperation.CHECKLIST_REMINDER_SENT.wireName(), sends.keySet());
        int sent = 0;
        List<Map.Entry<String, Pending>> queue = List.copyOf(sends.entrySet());
        for (int index = 0; index < queue.size(); index++) {
            Map.Entry<String, Pending> pending = queue.get(index);
            String key = pending.getKey();
            if (alreadySent.contains(key)) {
                sentUnmarked.remove(key);
                continue;
            }
            Pending message = pending.getValue();
            if (sentUnmarked.contains(key)) {
                // Sent this week, the mark refused: marked now if the log takes it, never sent again.
                if (!mark(key, message)) {
                    return stopped(sent, queue.subList(index + 1, queue.size()), alreadySent);
                }
                sentUnmarked.remove(key);
                continue;
            }
            try {
                mail.sendTextTo(List.of(message.address()), message.message().subject(), message.message().body());
            } catch (RuntimeException refused) {
                // No entry: the entry is what says it went, and its absence is what retries it next hour.
                log.warn("The weekly checklist reminder {} could not be sent; it will be retried next tick.",
                        key, refused);
                continue;
            }
            sent++;
            if (!mark(key, message)) {
                // **The run stops at the first mark refused.** The log is the bookkeeping, and with it
                // refusing writes every message after this one would go out unmarked too — and, before this
                // stop, every hour again, 168 times a week. What was sent is remembered here until the log
                // takes its mark.
                sentUnmarked.add(key);
                return stopped(sent, queue.subList(index + 1, queue.size()), alreadySent);
            }
        }
        return sent;
    }

    /**
     * Ends a run stopped by a refused mark, saying how many recipients wait: <b>while the audit log refuses
     * writes, nobody after the first recipient is written to</b> — the other contacts and the CISOs wait for
     * the log, and an outage spanning a whole week misses that week's reminder for them.
     */
    private int stopped(int sent, List<Map.Entry<String, Pending>> rest, Set<String> alreadySent) {
        long waiting = rest.stream()
                .filter(entry -> !alreadySent.contains(entry.getKey()) && !sentUnmarked.contains(entry.getKey()))
                .count();
        log.warn("The weekly checklist reminders stopped with the audit log refusing their mark: {} recipient(s) "
                + "not written to this run, until the log takes writes again.", waiting);
        return sent;
    }

    /**
     * The sends of this week whose mark the audit log refused, by key — held by this instance so that the
     * first recipient of a run, the only one written to before the run stops ({@link #stopped}), is not
     * written to again every hour while the log refuses. Lost with the process, which then sends that one
     * once more: a restart is rarer than the tick.
     */
    private final Set<String> sentUnmarked = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /**
     * Writes a send's mark through the call that says when it could not ({@code append}) — {@code record}
     * logs a refusal and returns, which here would read as a reminder never sent.
     *
     * @return whether the log took it
     */
    private boolean mark(String key, Pending message) {
        try {
            audit.append(new AuditLogService.Record(AuditOperation.CHECKLIST_REMINDER_SENT, key, message.description(),
                    // No actor: nobody asked for this one, as nobody asks for the posture report.
                    null, null, null));
            return true;
        } catch (RuntimeException refused) {
            log.error("The weekly checklist reminder {} was sent and could not be recorded; the run stops here, and "
                    + "it is not sent again.", key, refused);
            return false;
        }
    }

    /** A message due to one recipient: where it goes, what it says, and what its audit entry will say. */
    private record Pending(String address, ChecklistReminder.Message message, String description) {}

    /**
     * What is due this week: each reachable contact's lines, by account; each profile nobody is reminded for;
     * and, for the CISOs' visibility, each project's repositories as the guard reads them.
     */
    private record Due(Map<Long, List<ProfileLines>> byAccount, Map<Long, UserView> accounts, List<Unreached> unreached,
            Map<Long, List<Long>> repositoryIds) {}

    private Due due() {
        Map<Long, List<ProfileLines>> byAccount = new LinkedHashMap<>();
        Map<Long, UserView> reachable = new HashMap<>();
        List<Unreached> unreached = new ArrayList<>();
        Map<Long, List<Long>> repositoryIds = new HashMap<>();

        for (ChecklistEntity draft : checklists.findByStatusOrderByProjectIdAsc(ChecklistStatus.DRAFT.wireName())) {
            Optional<SolutionQueryService.ProjectMembers> members = projects.members(draft.getProjectId());
            if (members.isEmpty()) {
                continue; // a project deleted since: its rows go with it, in the same transaction
            }
            long projectId = draft.getProjectId();
            List<Long> repositories = members.get().repositoryIds();
            List<ChecklistItemEntity> lines = items.findByVersionIdOrderByPositionAsc(draft.getTemplateVersionId());
            Map<String, List<ChecklistItemEntity>> open = contactRules.unfilledByProfile(draft, lines);
            if (open.isEmpty()) {
                continue;
            }
            repositoryIds.put(projectId, repositories);
            Map<String, ChecklistContactEntity> links = new HashMap<>();
            contacts.findByProjectIdOrderByProfileAsc(projectId).forEach(link -> links.put(link.getProfile(), link));

            for (ContactProfiles.Profile profile : ContactProfiles.of(lines.stream().map(ChecklistItemEntity::getContact).toList())) {
                List<ChecklistItemEntity> theirs = open.get(profile.key());
                if (theirs == null) {
                    continue;
                }
                ChecklistContactEntity link = links.get(profile.key());
                Optional<UserView> account = link == null ? Optional.empty() : accounts.byId(link.getAccountId());
                Optional<Gap> gap = link == null ? Optional.of(Gap.NOBODY_LINKED)
                        : contactRules.gapOf(account, projectId, repositories);
                if (gap.isPresent()) {
                    unreached.add(new Unreached(projectId, members.get().name(), profile.label(), theirs.size(), gap.get()));
                    continue;
                }
                UserView contact = account.orElseThrow();
                reachable.put(contact.id(), contact);
                byAccount.computeIfAbsent(contact.id(), ignored -> new ArrayList<>()).add(new ProfileLines(projectId,
                        members.get().name(), profile.label(), theirs.stream()
                                .map(line -> new ChecklistReminder.Line(line.getPosition(), line.getControl()))
                                .toList()));
            }
        }
        return new Due(byAccount, reachable, unreached, repositoryIds);
    }
}
