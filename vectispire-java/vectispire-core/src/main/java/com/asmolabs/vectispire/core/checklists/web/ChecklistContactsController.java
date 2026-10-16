package com.asmolabs.vectispire.core.checklists.web;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresWriteAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.checklists.ChecklistContactCandidate;
import com.asmolabs.vectispire.core.checklists.ChecklistContactService;
import com.asmolabs.vectispire.core.checklists.ChecklistContactsView;
import com.asmolabs.vectispire.core.checklists.ProjectChecklistService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A project's checklist profiles — the values of its template's contact column — and the accounts they are
 * linked to, each reminded weekly of its lines still to fill in (decision 0044).
 *
 * <p><b>Every route names a project, and the service refuses it</b> as the checklist's own routes do: 404
 * "Project not found." for a project the caller does not see whole. Reading the list is any account's, the
 * auditor included; listing the accounts it may name and changing a link are a writer's, the roles that
 * answer the checklist.
 */
@Tag(name = "Project checklists")
@RestController
@RequestMapping("/api/v1/projects/{projectId}/checklists/contacts")
public class ChecklistContactsController {

    private final ChecklistContactService contacts;
    private final VisibilityService visibility;

    public ChecklistContactsController(ChecklistContactService contacts, VisibilityService visibility) {
        this.contacts = contacts;
        this.visibility = visibility;
    }

    /** @param accountId the account to link the profile to — one of the candidates */
    public record ChecklistContactRequest(Long accountId) {}

    @Operation(summary = "List checklist contacts", description = "The profiles the contact column of the project's "
            + "newest checklist version names — every value but AUTO, a cell such as \"PO / BA\" naming both, compared "
            + "without case — each with the account linked to it, the lines it still has to fill in in the draft, and "
            + "a warning when that account would not be reminded: account_gone, account_inactive, no_email, "
            + "cannot_fill to a caller who may relink it, not_reminded to one who may not. Empty while the project "
            + "has no checklist. 404 for a project the caller does not see whole.")
    @GetMapping
    @RequiresAccount
    public ChecklistContactsView checklistContacts(
            @PathVariable long projectId, @AuthenticationPrincipal VectispirePrincipal principal) {
        return contacts.contacts(projectId, allowanceOf(principal), writes(principal));
    }

    @Operation(summary = "List checklist contact candidates", description = "The accounts a profile of this project "
            + "may be linked to: active, of a role that answers checklists, and seeing the whole project — each by its "
            + "id and its display name, null when it has none or one that is an e-mail address; never its user name, "
            + "its address or its role. 404 for a project the caller does not see whole.")
    @GetMapping("/candidates")
    @RequiresWriteAccount
    public List<ChecklistContactCandidate> checklistContactCandidates(
            @PathVariable long projectId, @AuthenticationPrincipal VectispirePrincipal principal) {
        return contacts.candidates(projectId, allowanceOf(principal));
    }

    @Operation(summary = "Link checklist contact", description = "Links the profile — its key or the column's "
            + "spelling, compared without case — to an account, in place of the one it was linked to; audited. 400 "
            + "without accountId, or for an account that does not exist, is deactivated or cannot fill in this "
            + "project's checklist; 404 for a project not seen whole, and for a profile its newest checklist version "
            + "does not name.")
    @PutMapping("/{profile}")
    @RequiresWriteAccount
    public ChecklistContactsView linkChecklistContact(
            @PathVariable long projectId,
            @PathVariable String profile,
            @RequestBody ChecklistContactRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return contacts.link(projectId, profile, body == null ? null : body.accountId(), allowanceOf(principal),
                participant(principal, request));
    }

    @Operation(summary = "Unlink checklist contact", description = "Unlinks the profile: its lines are listed to the "
            + "CISOs until it is linked again. Unlinking a profile linked to nobody changes nothing. 404 for a project "
            + "the caller does not see whole.")
    @DeleteMapping("/{profile}")
    @RequiresWriteAccount
    public ChecklistContactsView unlinkChecklistContact(
            @PathVariable long projectId,
            @PathVariable String profile,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return contacts.unlink(projectId, profile, allowanceOf(principal), participant(principal, request));
    }

    /** Whether the caller may relink a profile — and so is told why an account would not be reminded. */
    private static boolean writes(VectispirePrincipal principal) {
        return principal.user().flatMap(user -> Role.of(user.role())).map(Role::canCauseEffects).orElse(false);
    }

    /** The caller's allowance: the account's grants, the projects granted as such, and the credential's narrowing. */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }

    private static ProjectChecklistService.Participant participant(VectispirePrincipal principal,
            HttpServletRequest request) {
        return new ProjectChecklistService.Participant(principal.requireUser(), RequestActors.of(principal, request));
    }
}
