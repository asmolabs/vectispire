package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleProject;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistReminder.Gap;
import com.asmolabs.vectispire.common.domain.checklists.ContactProfiles;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.AccountDirectory;
import com.asmolabs.vectispire.core.access.AccountNames;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistContactEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistContactRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistRepository;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

/**
 * Who a project's checklist profiles are — the values of its template's contact column, "PO", "Arch" —
 * linked to its accounts, so that each is reminded of its own lines (decision 0044).
 *
 * <p><b>The whole project, or nothing</b>, as every checklist route: the same guard as {@link
 * ProjectChecklistService}'s, answering "Project not found." for a project the caller does not see whole.
 *
 * <p><b>A profile is linked to an account that can fill the checklist in</b> — active, of a role that
 * writes ({@code canCauseEffects}), seeing the project whole as its own account. Linking somebody the
 * checklist would answer 404, or who may not answer a line, names a person who cannot do what the reminder
 * asks. Whether that stays true is asked again at every reminder, and at every read of the list: an account
 * deactivated, moved off the project or deleted since is shown, with its {@code warning}, and its lines go
 * to the CISOs.
 *
 * <p><b>The link is kept by the profile's key, not by a line</b>: it outlives the template version it was
 * made on, and the next version's column names the same profiles. A profile the newest version no longer
 * names is not listed, and its link waits, unused, for a version that names it again.
 *
 * <p><b>Every write is audited after it is stored</b>, like the checklist's own.
 */
@Service
public class ChecklistContactService {

    private final ChecklistRepository checklists;
    private final ChecklistItemRepository items;
    private final ChecklistAnswerRepository answers;
    private final ChecklistContactRepository contacts;
    private final SolutionQueryService projects;
    private final VisibilityService visibility;
    private final AccountDirectory accounts;
    private final AuditLogService audit;
    private final Clock clock;

    public ChecklistContactService(
            ChecklistRepository checklists,
            ChecklistItemRepository items,
            ChecklistAnswerRepository answers,
            ChecklistContactRepository contacts,
            SolutionQueryService projects,
            VisibilityService visibility,
            AccountDirectory accounts,
            AuditLogService audit,
            Clock clock) {
        this.checklists = checklists;
        this.items = items;
        this.answers = answers;
        this.contacts = contacts;
        this.projects = projects;
        this.visibility = visibility;
        this.accounts = accounts;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * What a reader who cannot write is told of an account that would not be reminded: that it would not,
     * and not why. Whether another person's account is deactivated, has no address or lost its access to
     * the project is the business of who can relink the profile — the writers, who are given the reason.
     */
    static final String NOT_REMINDED = "not_reminded";

    /**
     * The project's profiles, each with the account linked to it and the lines it has to fill in.
     *
     * @param detailed whether the caller may relink the profiles, and so is told why an account would not
     *     be reminded; otherwise only that it would not ({@link #NOT_REMINDED})
     */
    public ChecklistContactsView contacts(long projectId, VisibilityService.Allowance allowance, boolean detailed) {
        Guarded guarded = requireWhole(projectId, allowance);
        Optional<ChecklistEntity> latest = checklists.findFirstByProjectIdOrderByRevisionDesc(projectId);
        if (latest.isEmpty()) {
            return new ChecklistContactsView(projectId, null, false, List.of());
        }
        ChecklistEntity checklist = latest.get();
        boolean draft = ChecklistStatus.DRAFT.wireName().equals(checklist.getStatus());
        List<ChecklistItemEntity> lines = items.findByVersionIdOrderByPositionAsc(checklist.getTemplateVersionId());
        Map<String, List<ChecklistItemEntity>> open = draft ? unfilledByProfile(checklist, lines) : Map.of();
        Map<String, ChecklistContactEntity> linked = new LinkedHashMap<>();
        contacts.findByProjectIdOrderByProfileAsc(projectId).forEach(link -> linked.put(link.getProfile(), link));

        List<ChecklistContactView> profiles = new ArrayList<>();
        for (ContactProfiles.Profile profile : ContactProfiles.of(lines.stream().map(ChecklistItemEntity::getContact).toList())) {
            int openLines = open.getOrDefault(profile.key(), List.of()).size();
            ChecklistContactEntity link = linked.get(profile.key());
            if (link == null) {
                profiles.add(new ChecklistContactView(profile.key(), profile.label(), openLines, null, null, null));
                continue;
            }
            Optional<UserView> account = accounts.byId(link.getAccountId());
            profiles.add(new ChecklistContactView(profile.key(), profile.label(), openLines, link.getAccountId(),
                    account.flatMap(ChecklistContactService::nameOf).orElse(null),
                    gapOf(account, guarded.project().projectId(), guarded.repositoryIds())
                            .map(gap -> detailed ? gap.wireName() : NOT_REMINDED).orElse(null)));
        }
        return new ChecklistContactsView(projectId, checklist.getRevision(), draft, profiles);
    }

    /** The accounts a profile of this project may be linked to, by user name. */
    public List<ChecklistContactCandidate> candidates(long projectId, VisibilityService.Allowance allowance) {
        Guarded guarded = requireWhole(projectId, allowance);
        return accounts.active().stream()
                .filter(account -> canFill(account, guarded.project().projectId(), guarded.repositoryIds()))
                .map(account -> new ChecklistContactCandidate(account.id(), nameOf(account).orElse(null)))
                .toList();
    }

    /**
     * Links a profile to an account, replacing the account it was linked to.
     *
     * @param profile the profile's key or the column's spelling of it — compared as the column's values are
     */
    public ChecklistContactsView link(long projectId, String profile, Long accountId, VisibilityService.Allowance allowance,
            ProjectChecklistService.Participant who) {
        Guarded guarded = requireWhole(projectId, allowance);
        ContactProfiles.Profile named = requireProfile(guarded.project(), profile);
        if (accountId == null) {
            throw new InvalidInputException("Name the account to link the profile to: accountId.");
        }
        // One sentence for an account that does not exist and one that cannot fill the checklist in: the
        // route is a writer's, and a list of which ids hold an account is not what it is for.
        UserView account = accounts.byId(accountId)
                .filter(found -> found.isActive() && canFill(found, projectId, guarded.repositoryIds()))
                .orElseThrow(() -> new InvalidInputException("Account " + accountId + " cannot be linked: it does not "
                        + "exist, is deactivated, or cannot fill in this project's checklist."));

        Optional<Long> previous = store(projectId, named.key(), accountId, who.username());
        // By value: two boxed ids are the same object only up to 127, and an install has more accounts.
        if (previous.equals(Optional.of(accountId))) {
            return contacts(projectId, allowance, true);
        }
        audit.record(who.actor().entry(AuditOperation.CHECKLIST_CONTACT_CHANGED, resource(projectId, named.key()),
                "Checklist profile " + named.label() + " of project \"" + guarded.project().name() + "\" linked to account "
                        + account.id()
                        + previous.map(before -> ", in place of account " + before).orElse("") + "."));
        return contacts(projectId, allowance, true);
    }

    /** Unlinks a profile; its lines go to the CISOs until it is linked again. Unlinking an unlinked profile is not an error. */
    public ChecklistContactsView unlink(long projectId, String profile, VisibilityService.Allowance allowance,
            ProjectChecklistService.Participant who) {
        Guarded guarded = requireWhole(projectId, allowance);
        String key = ContactProfiles.keyOf(profile);
        // Not refused for a profile the newest version no longer names: its link is the one a screen cannot
        // show, and this is how it goes.
        Optional<ChecklistContactEntity> link = key.isEmpty() ? Optional.empty() : contacts.findByProjectIdAndProfile(projectId, key);
        if (link.isPresent() && contacts.deleteLink(projectId, key) > 0) {
            audit.record(who.actor().entry(AuditOperation.CHECKLIST_CONTACT_CHANGED, resource(projectId, key),
                    "Checklist profile " + key + " of project \"" + guarded.project().name() + "\" unlinked from account "
                            + link.get().getAccountId() + "."));
        }
        return contacts(projectId, allowance, true);
    }

    // ------------------------------------------------------------------ shared with the reminder

    /**
     * The lines of a draft still to fill in — no current answer, or a carried one waiting for confirmation —
     * grouped by the profiles their contact names, each line under each profile it names.
     */
    Map<String, List<ChecklistItemEntity>> unfilledByProfile(ChecklistEntity draft, List<ChecklistItemEntity> lines) {
        var current = ProjectChecklistService.currentOf(answers.findByChecklistIdOrderByIdAsc(draft.getId()));
        Map<String, List<ChecklistItemEntity>> open = new LinkedHashMap<>();
        for (ChecklistItemEntity line : lines) {
            var answer = current.get(line.getId());
            if (answer != null && !answer.isNeedsConfirmation()) {
                continue;
            }
            for (String key : ContactProfiles.keysOf(line.getContact())) {
                open.computeIfAbsent(key, ignored -> new ArrayList<>()).add(line);
            }
        }
        return open;
    }

    /**
     * Why an account linked to a profile would not be reminded of its lines, or nothing when it would: it is
     * gone, deactivated, no longer able to fill the checklist in, or has no address to write to — in that
     * order, the first being what a CISO acts on.
     */
    Optional<Gap> gapOf(Optional<UserView> account, long projectId, List<Long> repositoryIds) {
        if (account.isEmpty()) {
            return Optional.of(Gap.ACCOUNT_GONE);
        }
        UserView user = account.get();
        if (!user.isActive()) {
            return Optional.of(Gap.ACCOUNT_INACTIVE);
        }
        if (!canFill(user, projectId, repositoryIds)) {
            return Optional.of(Gap.CANNOT_FILL);
        }
        if (user.email() == null || user.email().isBlank()) {
            return Optional.of(Gap.NO_EMAIL);
        }
        return Optional.empty();
    }

    /**
     * Whether an account can fill in a project's checklist: a role that writes, and the project seen whole by
     * the account itself — the checklist routes' two conditions, with no credential narrowing it.
     */
    boolean canFill(UserView account, long projectId, List<Long> repositoryIds) {
        if (!Role.of(account.role()).map(Role::canCauseEffects).orElse(false)) {
            return false;
        }
        return RowVisibility.seesWholeProject(projectId, repositoryIds, visibility.allowance(account, Visibility.everything()));
    }

    /**
     * The name a list or a message may print: the display name, under {@link AccountNames}' rule, or none —
     * and the account is then named by its id. Never the user name: it is how the account signs in, and
     * through an identity provider often an address, and these lists are read by people who administer
     * nobody (decision 0044).
     */
    static Optional<String> nameOf(UserView account) {
        return AccountNames.displayNameOf(account);
    }

    // ------------------------------------------------------------------ the guard and the rows

    /** A project the guard let through, and the repositories it judged it by. */
    private record Guarded(VisibleProject project, List<Long> repositoryIds) {}

    private Guarded requireWhole(long projectId, VisibilityService.Allowance allowance) {
        Optional<SolutionQueryService.ProjectMembers> members = projects.members(projectId);
        List<Long> repositories = List.copyOf(
                members.map(SolutionQueryService.ProjectMembers::repositoryIds).orElse(List.of()));
        VisibleProject project = RowVisibility.requireWhollyVisibleProject(projectId,
                members.map(SolutionQueryService.ProjectMembers::name), repositories, allowance);
        return new Guarded(project, repositories);
    }

    /** A profile the newest version's contact column names, or 404 in the words of a profile that is not there. */
    private ContactProfiles.Profile requireProfile(VisibleProject project, String profile) {
        String key = ContactProfiles.keyOf(profile);
        return checklists.findFirstByProjectIdOrderByRevisionDesc(project.projectId())
                .map(checklist -> ContactProfiles.of(items.findByVersionIdOrderByPositionAsc(checklist.getTemplateVersionId())
                        .stream().map(ChecklistItemEntity::getContact).toList()))
                .orElse(List.of())
                .stream()
                .filter(named -> named.key().equals(key))
                .findFirst()
                .orElseThrow(() -> new NotFoundException("The checklist of project \"" + project.name()
                        + "\" names no profile \"" + (profile == null ? "" : profile.strip()) + "\"."));
    }

    /**
     * Stores the link, and answers the account it replaced. Two people linking the same profile at once both
     * find no row, and the unique key refuses the second insert: that one reads again and replaces the first
     * one's, as a link made a moment later would have.
     */
    private Optional<Long> store(long projectId, String key, long accountId, String linkedBy) {
        for (int attempt = 0; ; attempt++) {
            Optional<ChecklistContactEntity> existing = contacts.findByProjectIdAndProfile(projectId, key);
            ChecklistContactEntity row = existing.orElseGet(ChecklistContactEntity::new);
            Optional<Long> previous = existing.map(ChecklistContactEntity::getAccountId);
            if (previous.isPresent() && previous.get() == accountId) {
                return previous;
            }
            row.setProjectId(projectId);
            row.setProfile(key);
            row.setAccountId(accountId);
            row.setLinkedBy(linkedBy);
            row.setLinkedAt(clock.instant());
            try {
                contacts.saveAndFlush(row);
                return previous;
            } catch (DataIntegrityViolationException raced) {
                if (attempt > 0) {
                    throw raced;
                }
            }
        }
    }

    private static String resource(long projectId, String key) {
        return projectId + "/contacts/" + key;
    }
}
