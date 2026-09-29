package com.asmolabs.vectispire.core.checklists.web;

import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.access.web.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.checklists.ChecklistItemEvidence;
import com.asmolabs.vectispire.core.checklists.ChecklistItemPair;
import com.asmolabs.vectispire.core.checklists.ChecklistLayoutForm;
import com.asmolabs.vectispire.core.checklists.ChecklistTemplatePreview;
import com.asmolabs.vectispire.core.checklists.ChecklistTemplateService;
import com.asmolabs.vectispire.core.checklists.ChecklistTemplateView;
import com.asmolabs.vectispire.core.checklists.ChecklistVersionView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * The organisation's checklist templates and their versions (decision 0032 §3, §4, §8).
 *
 * <p><b>Organisation-wide, not target-scoped.</b> A template is the organisation's own checklist: it
 * names no repository, no image, no project, and describes nobody's estate — so no route resolves a
 * visibility, and the roles decide. Writing one — importing a workbook, confirming a draft's layout
 * and words, pairing its items, setting what proof its lines ask for, deriving, publishing, retiring —
 * is {@code @RequiresSecurityLead}, the roles that {@code canWriteGovernance}: the platform governor, an
 * administrator, a CISO. Reading one
 * is {@code @RequiresGovernanceRead}, which adds the auditor: the words an organisation asks its teams
 * to attest to are governance, and the auditor reads everything and writes nothing. With four-eyes
 * on, the service refuses an author of a version as its publisher.
 *
 * <p>The workbook arrives as the raw body — there is no multipart route, and the body filter bounds a
 * raw body where it could not bound a part — capped at {@code
 * vectispire.http.max-body.checklist-template-import} before it is read.
 *
 * <p><b>A 409 names its cause</b> in the problem's {@code type}, {@code urn:vectispire:problem:}
 * followed by one of: {@code checklist-template-not-draft} (published or retired — derive a new
 * version), {@code checklist-template-no-layout}, {@code checklist-template-changed} (changed since the
 * revision named — read it again), {@code checklist-template-has-draft} (one draft at a time), {@code
 * checklist-template-not-published} (derived from a draft or a retired version), {@code
 * checklist-template-retired}, {@code checklist-template-nothing-to-pair}, and {@code
 * checklist-four-eyes}, the project checklists' own token, since it means the same there.
 */
@Tag(name = "Checklist templates", description = "The organisation's checklist templates, imported from its "
        + "workbooks. A 409 names its cause in the problem's type, urn:vectispire:problem:<cause>: "
        + "checklist-template-not-draft, checklist-template-no-layout, checklist-template-changed, "
        + "checklist-template-has-draft, checklist-template-not-published, checklist-template-retired, "
        + "checklist-template-nothing-to-pair, checklist-four-eyes.")
@RestController
@RequestMapping("/api/v1/checklist-templates")
public class ChecklistTemplatesController {

    private final ChecklistTemplateService templates;

    public ChecklistTemplatesController(ChecklistTemplateService templates) {
        this.templates = templates;
    }

    /** @param pairs every pair the draft is to have: an empty list clears them */
    public record ChecklistPairsRequest(List<ChecklistItemPair> pairs) {}

    /** @param items the lines whose requirement changes; a line not listed keeps its own */
    public record ChecklistEvidenceRequest(List<ChecklistItemEvidence> items) {}

    /** @param label how the new version is known, beside its number; optional */
    public record ChecklistDeriveRequest(String label) {}

    /** @param revision the draft's revision the publisher reviewed */
    public record ChecklistPublishRequest(Integer revision) {}

    @Operation(summary = "List checklist templates", description = "Every template, with its versions and without "
            + "their items.")
    @GetMapping
    @RequiresGovernanceRead
    public List<ChecklistTemplateView> listTemplates() {
        return templates.list();
    }

    @Operation(summary = "Read checklist template", description = "404 for a slug no template has.")
    @GetMapping("/{slug}")
    @RequiresGovernanceRead
    public ChecklistTemplateView readTemplate(@PathVariable String slug) {
        return templates.template(slug);
    }

    @Operation(summary = "Import checklist template workbook", description = "Security lead only. The .xlsx is the "
            + "raw body; it becomes the template's next version, a draft, whose layout is then confirmed — never "
            + "published in one step. A new slug creates the template, named by name. 400 for a body that is not an "
            + ".xlsx workbook or fails a zip or XML guard; 409 checklist-template-has-draft while the template has a "
            + "draft; 413 past the size ceiling.")
    @PostMapping(value = "/{slug}/versions", consumes = {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/octet-stream"})
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresSecurityLead
    public ChecklistVersionView importWorkbook(
            @PathVariable String slug,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) String label,
            @RequestBody byte[] workbook,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return templates.importWorkbook(slug, name, label, workbook, editor(principal, request));
    }

    @Operation(summary = "Read checklist template version", description = "Its status, its confirmed layout, its "
            + "items in the sheet's order and its pairs made by hand.")
    @GetMapping("/{slug}/versions/{ordinal}")
    @RequiresGovernanceRead
    public ChecklistVersionView readVersion(@PathVariable String slug, @PathVariable int ordinal) {
        return templates.version(slug, ordinal);
    }

    @Operation(summary = "Preview checklist template version", description = "The layout the reader proposes from "
            + "the workbook's structure, the confirmed one, the cells of a sheet, and each item's pairing with the "
            + "previous version. sheet names the sheet whose cells to show.")
    @GetMapping("/{slug}/versions/{ordinal}/preview")
    @RequiresGovernanceRead
    public ChecklistTemplatePreview previewVersion(
            @PathVariable String slug, @PathVariable int ordinal, @RequestParam(required = false) String sheet) {
        return templates.preview(slug, ordinal, sheet);
    }

    @Operation(summary = "Confirm checklist template layout", description = "Security lead only, on a draft. The "
            + "sheet, the column of each field, the item rows, the header cells and the answer words; the items are "
            + "read from the workbook by it, and pairs made earlier are cleared. revision is the one the editor read. 400 "
            + "for a layout that cannot be one, or without revision; 409 checklist-template-not-draft, "
            + "checklist-template-changed (changed since that revision).")
    @PutMapping("/{slug}/versions/{ordinal}/layout")
    @RequiresSecurityLead
    public ChecklistVersionView confirmLayout(
            @PathVariable String slug,
            @PathVariable int ordinal,
            @RequestParam(required = false) Integer revision,
            @RequestBody ChecklistLayoutForm layout,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return templates.confirmLayout(slug, ordinal, revision, layout, editor(principal, request));
    }

    @Operation(summary = "Pair checklist template items", description = "Security lead only, on a draft with a "
            + "confirmed layout. Each pair says an item the draft adds is one the previous version removes, reworded: "
            + "it takes the old key, and a project's answer follows it, to be confirmed. The list replaces the "
            + "draft's pairs. revision is the one the editor read. 400 for a pair of items that are not added and "
            + "removed, or without revision; 409 checklist-template-not-draft, "
            + "checklist-template-no-layout, checklist-template-nothing-to-pair (no previous version), "
            + "checklist-template-changed.")
    @PutMapping("/{slug}/versions/{ordinal}/pairs")
    @RequiresSecurityLead
    public ChecklistVersionView pairItems(
            @PathVariable String slug,
            @PathVariable int ordinal,
            @RequestParam(required = false) Integer revision,
            @RequestBody ChecklistPairsRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return templates.pairItems(slug, ordinal, revision, body == null ? null : body.pairs(),
                editor(principal, request));
    }

    @Operation(summary = "Set checklist template evidence requirements", description = "Security lead only, on a "
            + "draft with a confirmed layout. For each line named by its itemKey: the proof a yes needs before a "
            + "checklist can be submitted — evidenceKind none, link_or_file or file — and, for a proof that expires, "
            + "evidenceValidityMonths, 1 to 120. Lines not listed keep theirs. The requirement is part of the line's "
            + "content digest: a line whose requirement moved is changed against the previous version, and a "
            + "project's answer carried onto it waits for confirmation. revision is the one the editor read. 400 "
            + "without revision or lines, for a line named twice or not in the version, a requirement that is none, a "
            + "validity out of bounds or on a line asking for no proof; 409 checklist-template-not-draft, "
            + "checklist-template-no-layout, checklist-template-changed.")
    @PutMapping("/{slug}/versions/{ordinal}/evidence")
    @RequiresSecurityLead
    public ChecklistVersionView setEvidence(
            @PathVariable String slug,
            @PathVariable int ordinal,
            @RequestParam(required = false) Integer revision,
            @RequestBody ChecklistEvidenceRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return templates.setEvidence(slug, ordinal, revision, body == null ? null : body.items(),
                editor(principal, request));
    }

    @Operation(summary = "Derive checklist template version", description = "Security lead only. A new draft from a "
            + "published version: the same workbook, layout and items. 409 checklist-template-not-published, "
            + "checklist-template-has-draft.")
    @PostMapping("/{slug}/versions/{ordinal}/derive")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresSecurityLead
    public ChecklistVersionView deriveVersion(
            @PathVariable String slug,
            @PathVariable int ordinal,
            @RequestBody(required = false) ChecklistDeriveRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return templates.derive(slug, ordinal, body == null ? null : body.label(), editor(principal, request));
    }

    @Operation(summary = "Publish checklist template version", description = "Security lead only, on a draft with a "
            + "confirmed layout, naming the revision reviewed. With four-eyes approval on, not by one of its authors. "
            + "400 without revision; 409 checklist-template-not-draft, checklist-template-no-layout, "
            + "checklist-template-changed (changed since the revision named), checklist-four-eyes (written by the "
            + "caller while four-eyes is on).")
    @PostMapping("/{slug}/versions/{ordinal}/publish")
    @RequiresSecurityLead
    public ChecklistVersionView publishVersion(
            @PathVariable String slug,
            @PathVariable int ordinal,
            @RequestBody ChecklistPublishRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return templates.publish(slug, ordinal, body == null ? null : body.revision(), editor(principal, request));
    }

    @Operation(summary = "Retire checklist template version", description = "Security lead only. A published version "
            + "stops being offered for new checklists — with four-eyes approval on, not by one of its authors — and a "
            + "draft is set aside. 409 checklist-template-retired, "
            + "checklist-four-eyes, checklist-template-changed.")
    @PostMapping("/{slug}/versions/{ordinal}/retire")
    @RequiresSecurityLead
    public ChecklistVersionView retireVersion(
            @PathVariable String slug,
            @PathVariable int ordinal,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return templates.retire(slug, ordinal, editor(principal, request));
    }

    private static ChecklistTemplateService.Editor editor(VectispirePrincipal principal, HttpServletRequest request) {
        return new ChecklistTemplateService.Editor(principal.requireUser().id(), RequestActors.of(principal, request));
    }
}
