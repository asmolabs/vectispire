package com.asmolabs.vectispire.core.forges.web;

import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.forges.ForgeImportService;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeCandidatePage;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportPreview;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportRequest;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportResult;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeSelection;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeSelectionChange;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeSelectionFilters;
import com.asmolabs.vectispire.core.forges.ForgeSelectionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Selecting a discovery's repositories and importing them as targets (decision 0037 §4–5). Administrators only, as
 * for the connection and its discoveries: the table lists repositories no grant covers yet, and an import creates
 * targets — both an administrator's. Integration keys are not accepted in v1. The services read, plan and write;
 * this maps the requests.
 */
@Tag(name = "Forge connections", description = "Read-only credentials to GitHub and GitLab, for discovering repositories")
@RestController
@RequestMapping("/api/v1/forge-connections/{connectionId}")
@RequiresAdministrator
public class ForgeImportsController {

    private final ForgeSelectionService selection;
    private final ForgeImportService imports;

    public ForgeImportsController(ForgeSelectionService selection, ForgeImportService imports) {
        this.selection = selection;
        this.imports = imports;
    }

    @Operation(summary = "List forge import candidates", description = "The repositories a discovery listed, as the "
            + "selection table shows them, by full path: each with presentAs (the targets whose URL has the identity of "
            + "its HTTPS or SSH clone URL, whatever their branch and sub-path), importedAs (the target an earlier import "
            + "from this connection made of it), selectable and notSelectable (already_imported, already_present, "
            + "no_default_branch, no_clone_url), offered (proposed ticked: selectable, not archived, not a fork, not in a "
            + "personal namespace) and the proposed solution and project. Filters: archived and forks hide (default), "
            + "show or only; inactiveDays hides a last activity older than that; language, visibility; namespace (and "
            + "below); path, a pattern (* any run, ? one) or a search; personal and present show (default), hide or only. "
            + "A filter that meets a value the forge did not give keeps it when it hides and leaves it out when it "
            + "requires; unjudged counts them per filter. limit 1 to 500 (100), offset a multiple of it. The discovery is "
            + "the connection's latest that completed or ended partial: 409 forge-discovery-not-selectable (state) for a "
            + "pending, running or failed one, 409 forge-discovery-superseded (latestDiscoveryId) for an older one.")
    @GetMapping("/discoveries/{discoveryId}/selection")
    public ForgeCandidatePage listForgeImportCandidates(
            @PathVariable UUID connectionId,
            @PathVariable long discoveryId,
            @RequestParam(required = false) String archived,
            @RequestParam(required = false) String forks,
            @RequestParam(required = false) Integer inactiveDays,
            @RequestParam(required = false) String language,
            @RequestParam(required = false) String visibility,
            @RequestParam(required = false) String namespace,
            @RequestParam(required = false) String path,
            @RequestParam(required = false) String personal,
            @RequestParam(required = false) String present,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false) Integer offset) {
        return selection.candidates(connectionId, discoveryId, new ForgeSelectionFilters(archived, forks, inactiveDays,
                language, visibility, namespace, path, personal, present), limit, offset);
    }

    @Operation(summary = "Change forge import selection", description = "Applies one operation to the selection — a "
            + "set of forge ids the screen holds — over what the filters match: proposed (the selectable repositories "
            + "they match, personal namespaces left out), all, none, invert, or add and remove with forgeIds. Answers "
            + "the selection in the table's order; a forge id that is not selectable (already a target, empty, not "
            + "listed) is dropped and named in dropped. At most 20,000 forge ids. Nothing is written.")
    @PostMapping("/discoveries/{discoveryId}/selection")
    public ForgeSelection changeForgeImportSelection(
            @PathVariable UUID connectionId,
            @PathVariable long discoveryId,
            @RequestBody(required = false) ForgeSelectionChange body) {
        return selection.select(connectionId, discoveryId, body);
    }

    @Operation(summary = "Preview forge import", description = "What importing the selected repositories would do, "
            + "nothing written: the targets to create with their URL, default branch, credential, solution and project, "
            + "who will see them (visibleTo) and their first scan; the repositories skipped and why (already_imported, "
            + "already_present with the targets, no_default_branch, no_clone_url, duplicate_in_selection); those the "
            + "import would refuse and the form's reason; the solutions and projects reused (existingId, with the "
            + "accounts and teams a reused project is granted to) or created (no grant); the credential per host, "
            + "proposed when the request names none — the one HTTPS token bound to the host, or none; the default "
            + "schedule in days; the visibility mode; the first scans. Body: discoveryId, forgeIds (at most 1,000), "
            + "mapping (rules per namespacePath or forgeId: solution, project or noProject), credentials (host, sshKeyId "
            + "or httpsTokenId), firstScan (false), spacingSeconds (10 to 600, 60), requiredAgentLabel.")
    @PostMapping("/imports/preview")
    public ForgeImportPreview previewForgeImport(
            @PathVariable UUID connectionId, @RequestBody(required = false) ForgeImportRequest body) {
        return selection.preview(connectionId, body);
    }

    @Operation(summary = "Import forge repositories", description = "Creates the selected repositories as targets, "
            + "in one transaction — everything or nothing — through the repository and solution forms' own gestures: the "
            + "same refusals (400 naming the first repositories refused; the preview lists them all), the same audit "
            + "entries, one per target, solution and project created, with where each target came from. Planned again "
            + "inside the transaction: whatever became a target since the preview is skipped, so replaying an import "
            + "creates nothing. Branch: the default branch at discovery; no schedule of its own, so the installation's "
            + "default applies at each target's own slot; no grant. First scans when asked, one every spacingSeconds "
            + "(not_before). The body is the preview's. One FORGE_IMPORT_APPLIED entry summarises the import, signalled "
            + "VECTI-SEC-035 once when it created something.")
    @PostMapping("/imports")
    public ForgeImportResult importForgeRepositories(
            @PathVariable UUID connectionId,
            @RequestBody(required = false) ForgeImportRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return imports.apply(connectionId, body, RequestActors.of(principal, request));
    }
}
