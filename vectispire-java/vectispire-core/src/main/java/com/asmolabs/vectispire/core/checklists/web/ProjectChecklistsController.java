package com.asmolabs.vectispire.core.checklists.web;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresWriteAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.checklists.ChecklistDocumentDownload;
import com.asmolabs.vectispire.core.checklists.ChecklistDocumentService;
import com.asmolabs.vectispire.core.checklists.ChecklistEvidenceDownload;
import com.asmolabs.vectispire.core.checklists.ChecklistLineHistory;
import com.asmolabs.vectispire.core.checklists.ChecklistMeasurementsView;
import com.asmolabs.vectispire.core.checklists.ChecklistOfferedVersion;
import com.asmolabs.vectispire.core.checklists.ChecklistProjectContext;
import com.asmolabs.vectispire.core.checklists.ChecklistRevisionSummary;
import com.asmolabs.vectispire.core.checklists.ChecklistView;
import com.asmolabs.vectispire.core.checklists.ProjectChecklistService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * A project's checklists, answered by people (decision 0032 §5, §8).
 *
 * <p><b>Every route names a project, and the service refuses it.</b> Each resolves the caller's
 * allowance — the account's grants intersected with the credential's restriction — and hands it on;
 * the service answers 404 "Project not found." for a project that does not exist, one the caller sees
 * nothing of, and one it sees only part of (open question 5). Reading is {@code @RequiresAccount} —
 * the auditor reads; writing is {@code @RequiresWriteAccount}, the roles that {@code canCauseEffects};
 * signing off is further an approver's ({@code canApproveTriage}), which no marker holds exactly, so
 * the service refuses the others 403 before it reads anything.
 *
 * <p><b>Every write names the edition its writer read</b> ({@code edition}): absent is 400, stale is
 * 409. A 409 names its cause in the problem's {@code type}, {@code urn:vectispire:problem:} followed by
 * one of: {@code checklist-changed} (the revision changed since that edition — read it again), {@code
 * checklist-line-changed} (the line did), {@code checklist-not-draft}, {@code checklist-not-submitted},
 * {@code checklist-not-signed-off}, {@code checklist-not-latest}, {@code checklist-incomplete}, {@code
 * checklist-four-eyes}, {@code checklist-version-not-published}, {@code checklist-same-version},
 * {@code checklist-nothing-to-confirm}, {@code checklist-evidence-withdrawn}, {@code
 * checklist-measurement-contradicted}, {@code checklist-measurement-changed}. A {@code
 * checklist-incomplete} problem also names its lines as data, in a {@code lines} member — each line's
 * {@code itemId}, {@code position} and {@code problems} — so that a client shows them in its own words;
 * so do the two measurement causes, each line with its answer and the measurement's outcome and reason.
 *
 * <p>A proof's file arrives as the raw body — there is no multipart route, and the body filter bounds
 * a raw body where it could not bound a part — capped at {@code
 * vectispire.http.max-body.checklist-evidence}, and goes back only as a download.
 */
@Tag(name = "Project checklists", description = "A project's security checklist, answered by people. A 409 names "
        + "its cause in the problem's type, urn:vectispire:problem:<cause>: checklist-changed, checklist-line-changed, "
        + "checklist-not-draft, checklist-not-submitted, checklist-not-signed-off, checklist-not-latest, "
        + "checklist-incomplete, checklist-four-eyes, checklist-version-not-published, checklist-same-version, "
        + "checklist-nothing-to-confirm, checklist-evidence-withdrawn, checklist-measurement-contradicted, "
        + "checklist-measurement-changed.")
@RestController
@RequestMapping("/api/v1/projects/{projectId}/checklists")
public class ProjectChecklistsController {

    private final ProjectChecklistService checklists;
    private final ChecklistDocumentService documents;
    private final VisibilityService visibility;

    public ProjectChecklistsController(ProjectChecklistService checklists, ChecklistDocumentService documents,
            VisibilityService visibility) {
        this.checklists = checklists;
        this.documents = documents;
        this.visibility = visibility;
    }

    /**
     * @param template the template's slug
     * @param version the published version's number
     * @param edition the edition of the project's newest revision the person read; absent when they saw no
     *     checklist on the project
     */
    public record ChecklistOpenRequest(String template, Integer version, Integer edition) {}

    /**
     * @param value {@code yes}, {@code no} or {@code not_applicable}; the comment is required but for yes
     * @param measurementDigest the {@code evidenceDigest} of the line's measurement the person read, for an
     *     answer resting on it — the one click a measured line offers; absent for an answer resting on none
     */
    public record ChecklistAnswerRequest(String value, String comment, String measurementDigest, Integer edition) {}

    /** @param edition the edition the person read */
    public record ChecklistEditionRequest(Integer edition) {}

    /** @param performedOn the day the work was done, {@code yyyy-MM-dd} */
    public record ChecklistLinkRequest(String link, String performedOn, Integer edition) {}

    public record ChecklistReturnRequest(String reason, Integer edition) {}

    @Operation(summary = "List project checklists", description = "Every revision of the project's checklist, newest "
            + "first. 404 for a project the caller does not see whole.")
    @GetMapping
    @RequiresAccount
    public List<ChecklistRevisionSummary> list(
            @PathVariable long projectId, @AuthenticationPrincipal VectispirePrincipal principal) {
        return checklists.list(projectId, allowanceOf(principal));
    }

    @Operation(summary = "Read project checklist context", description = "The project's name, as a checklist's "
            + "header states the product, and its newest revision and edition — null while it has no checklist, "
            + "which is the edition opening one names. 404 for a project the caller does not see whole.")
    @GetMapping("/context")
    @RequiresAccount
    public ChecklistProjectContext context(
            @PathVariable long projectId, @AuthenticationPrincipal VectispirePrincipal principal) {
        return checklists.context(projectId, allowanceOf(principal));
    }

    @Operation(summary = "List checklist versions offered to a project", description = "The published template "
            + "versions the project's checklist may be opened on or moved to. 404 for a project the caller does not "
            + "see whole.")
    @GetMapping("/offered")
    @RequiresAccount
    public List<ChecklistOfferedVersion> offered(
            @PathVariable long projectId, @AuthenticationPrincipal VectispirePrincipal principal) {
        return checklists.offered(projectId, allowanceOf(principal));
    }

    @Operation(summary = "Open project checklist", description = "Opens the project's checklist on a published "
            + "version, or moves it to another: a new revision, the previous one's answers carried — current where the "
            + "line is unchanged, awaiting confirmation where it changed. edition is the newest revision's, as read; "
            + "absent when the person saw none. 400 without template and version; 404 for a project not seen whole or "
            + "a version that does not exist; 409 checklist-version-not-published, checklist-changed (a checklist "
            + "opened or changed since), checklist-same-version.")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresWriteAccount
    public ChecklistView open(
            @PathVariable long projectId,
            @RequestBody ChecklistOpenRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.open(projectId, allowanceOf(principal), body == null ? null : body.template(),
                body == null ? null : body.version(), body == null ? null : body.edition(), participant(principal, request));
    }

    @Operation(summary = "Read project checklist", description = "One revision: its header, its lines with their "
            + "current answer, proofs and what keeps each from a submission, and its authors. 404 for a project not "
            + "seen whole or a revision it does not have.")
    @GetMapping("/{revision}")
    @RequiresAccount
    public ChecklistView read(
            @PathVariable long projectId,
            @PathVariable int revision,
            @AuthenticationPrincipal VectispirePrincipal principal) {
        return checklists.read(projectId, revision, allowanceOf(principal));
    }

    @Operation(summary = "Read checklist line history", description = "Every answer given on the line in this "
            + "revision, with its author and instant, oldest first — never edited — and every proof, withdrawn ones "
            + "included.")
    @GetMapping("/{revision}/items/{itemId}/history")
    @RequiresAccount
    public ChecklistLineHistory history(
            @PathVariable long projectId,
            @PathVariable int revision,
            @PathVariable long itemId,
            @AuthenticationPrincipal VectispirePrincipal principal) {
        return checklists.history(projectId, revision, itemId, allowanceOf(principal));
    }

    @Operation(summary = "Read checklist measurements", description = "The lines bound to a rule, each with what "
            + "the rule finds — outcome pass, fail or no_data with its reason, the instant it is as of, the evidence "
            + "per repository (the scan or import read, its date and digest) and the figures — beside the line's "
            + "answer and their reconciliation. For a draft or a submitted revision the measurements are computed for "
            + "this read and stored nowhere (id null); a submitted one also carries those of its submission; a "
            + "signed-off one's are those frozen by the sign-off. 404 for a project the caller does not see whole or a "
            + "revision it does not have.")
    @GetMapping("/{revision}/measurements")
    @RequiresAccount
    public ChecklistMeasurementsView measurements(
            @PathVariable long projectId,
            @PathVariable int revision,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.measurements(projectId, revision, allowanceOf(principal), participant(principal, request));
    }

    @Operation(summary = "Answer checklist line", description = "On a draft: a new answer, the caller its author. "
            + "no and not_applicable need a comment. measurementDigest, the evidenceDigest of the line's measurement "
            + "as read, rests the answer on that measurement, applied again and stored with it. edition is the one "
            + "read. 400 for no edition, an answer that is none, a negative one without its comment, not_applicable "
            + "on a version that does not offer it, a measurement named on a line bound to no rule; 409 "
            + "checklist-not-draft, checklist-line-changed, checklist-changed, checklist-measurement-changed (the "
            + "measurement is not the one read).")
    @PostMapping("/{revision}/items/{itemId}/answers")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresWriteAccount
    public ChecklistView answer(
            @PathVariable long projectId,
            @PathVariable int revision,
            @PathVariable long itemId,
            @RequestBody ChecklistAnswerRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.answer(projectId, revision, itemId, allowanceOf(principal), body == null ? null : body.value(),
                body == null ? null : body.comment(), body == null ? null : body.measurementDigest(),
                body == null ? null : body.edition(), participant(principal, request));
    }

    @Operation(summary = "Confirm carried checklist answer", description = "On a draft: the answer carried onto a "
            + "line that changed still holds, under the caller's name. 409 checklist-nothing-to-confirm, and those of "
            + "answering.")
    @PostMapping("/{revision}/items/{itemId}/confirmation")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresWriteAccount
    public ChecklistView confirm(
            @PathVariable long projectId,
            @PathVariable int revision,
            @PathVariable long itemId,
            @RequestBody ChecklistEditionRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.confirm(projectId, revision, itemId, allowanceOf(principal), body == null ? null : body.edition(),
                participant(principal, request));
    }

    @Operation(summary = "Attach link to checklist line", description = "On a draft: an https: or http: link, at most "
            + "2,000 characters, and the day the work was done. 400 for a link or a day that is none, a day in the "
            + "future; 409 as for answering.")
    @PostMapping("/{revision}/items/{itemId}/evidence/links")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresWriteAccount
    public ChecklistView attachLink(
            @PathVariable long projectId,
            @PathVariable int revision,
            @PathVariable long itemId,
            @RequestBody ChecklistLinkRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.attachLink(projectId, revision, itemId, allowanceOf(principal), body == null ? null : body.link(),
                body == null ? null : body.performedOn(), body == null ? null : body.edition(),
                participant(principal, request));
    }

    @Operation(summary = "Attach file to checklist line", description = "On a draft: the file as the raw body, its "
            + "Content-Type stored and never trusted, 25 MB at most; name, performedOn (yyyy-MM-dd) and edition. "
            + "Served back only as a download. 400 for an empty body, no name, no day; 413 past the ceiling; 409 as "
            + "for answering.")
    @PostMapping(value = "/{revision}/items/{itemId}/evidence/files", consumes = MediaType.ALL_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresWriteAccount
    public ChecklistView attachFile(
            @PathVariable long projectId,
            @PathVariable int revision,
            @PathVariable long itemId,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) String performedOn,
            @RequestParam(required = false) Integer edition,
            @RequestHeader(value = HttpHeaders.CONTENT_TYPE, required = false) String contentType,
            @RequestBody byte[] content,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.attachFile(projectId, revision, itemId, allowanceOf(principal), name, contentType, performedOn,
                content, edition, participant(principal, request));
    }

    @Operation(summary = "Download checklist proof", description = "An uploaded proof's bytes, always as an "
            + "attachment and as application/octet-stream — the declared type is never trusted to render. 404 for a "
            + "link, or a proof this revision does not have.")
    @GetMapping("/{revision}/evidence/{evidenceId}/file")
    @RequiresAccount
    public ResponseEntity<byte[]> download(
            @PathVariable long projectId,
            @PathVariable int revision,
            @PathVariable long evidenceId,
            @AuthenticationPrincipal VectispirePrincipal principal) {
        ChecklistEvidenceDownload file = checklists.download(projectId, revision, evidenceId, allowanceOf(principal));
        // An uploaded HTML or SVG file served inline would be a script on the control plane's origin: an
        // attachment, an opaque type and no sniffing, whatever the uploader declared. The filter chain's
        // default headers send nosniff on every response already; it is stated here as well, so that this
        // download does not rest on a default somebody may one day switch off for another route.
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(file.fileName(), StandardCharsets.UTF_8).build().toString())
                .header("X-Content-Type-Options", "nosniff")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(file.content());
    }

    @Operation(summary = "Download checklist document", description = "A zip: checklist.xlsx — the template's own "
            + "workbook with the answers, comments and header written in and an Evidence sheet added — and "
            + "checklist.json, the same statement machine-readable. For a signed-off revision, the package rendered "
            + "and signed at its sign-off, served as stored, with checklist.xlsx.sig and checklist.json.sig: detached "
            + "signatures to check with cosign verify-blob --key against /api/v1/crypto/public-key.pub. For any other "
            + "revision, rendered for this request, unsigned, its Evidence sheet opening with \"Draft — not signed "
            + "off\". Always an attachment. Accepts an integration key with the export scope; 404 for a project not "
            + "seen whole — a key restricted to one repository included — or a revision it does not have.")
    @ApiResponse(responseCode = "200", description = "The document, application/zip",
            content = @Content(mediaType = "application/zip", schema = @Schema(type = "string", format = "binary")))
    @GetMapping(value = "/{revision}/document", produces = "application/zip")
    @RequiresAccount
    @AcceptsApiKey(ApiKeyScope.EXPORT)
    public ResponseEntity<byte[]> checklistDocument(
            @PathVariable long projectId,
            @PathVariable int revision,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        ChecklistDocumentDownload document = documents.export(projectId, revision, allowanceOf(principal),
                RequestActors.of(principal, request));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(document.fileName(), StandardCharsets.UTF_8).build().toString())
                .header("X-Content-Type-Options", "nosniff")
                .contentType(MediaType.parseMediaType("application/zip"))
                .body(document.content());
    }

    @Operation(summary = "Withdraw checklist proof", description = "On a draft: the proof stops counting; its row "
            + "stays, dated and attributed. 409 checklist-evidence-withdrawn, and those of answering.")
    @PostMapping("/{revision}/evidence/{evidenceId}/withdrawal")
    @RequiresWriteAccount
    public ChecklistView withdraw(
            @PathVariable long projectId,
            @PathVariable int revision,
            @PathVariable long evidenceId,
            @RequestBody ChecklistEditionRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.withdraw(projectId, revision, evidenceId, allowanceOf(principal),
                body == null ? null : body.edition(), participant(principal, request));
    }

    @Operation(summary = "Submit project checklist", description = "A draft, at the edition read, for sign-off: every "
            + "line answered, every negative answer commented, every proof a yes needs attached and in date, no carried "
            + "answer awaiting confirmation. The lines bound to a rule are measured again and reconciled: a yes where "
            + "the measurement fails is refused, a yes where it has no data needs a comment and a proof in date; the "
            + "measurements are stored with the submission. 409 checklist-not-draft, checklist-changed, "
            + "checklist-incomplete — whose problem names the lines in its lines member as well as in its detail: each "
            + "line's itemId, position and problems, the tokens a line's view carries — and "
            + "checklist-measurement-contradicted, its lines in the same member.")
    // Declaring the 409 drops the 200 springdoc would infer, so it is declared too, as it was inferred.
    @ApiResponse(responseCode = "200", description = "OK",
            content = @Content(mediaType = "*/*", schema = @Schema(implementation = ChecklistView.class)))
    @ApiResponse(responseCode = "409", description = "The revision cannot be submitted; checklist-incomplete and "
            + "checklist-measurement-contradicted name their lines",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(oneOf = {
                    ChecklistRefusals.Incomplete.class, ChecklistRefusals.Measured.class})))
    @PostMapping("/{revision}/submission")
    @RequiresWriteAccount
    public ChecklistView submit(
            @PathVariable long projectId,
            @PathVariable int revision,
            @RequestBody ChecklistEditionRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.submit(projectId, revision, allowanceOf(principal), body == null ? null : body.edition(),
                participant(principal, request));
    }

    @Operation(summary = "Return project checklist", description = "A submitted revision back to its authors, a draft "
            + "again, with the reason. 400 without a reason; 409 checklist-not-submitted, checklist-changed.")
    @PostMapping("/{revision}/return")
    @RequiresWriteAccount
    public ChecklistView returnToAuthors(
            @PathVariable long projectId,
            @PathVariable int revision,
            @RequestBody ChecklistReturnRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.returnToAuthors(projectId, revision, allowanceOf(principal), body == null ? null : body.reason(),
                body == null ? null : body.edition(), participant(principal, request));
    }

    @Operation(summary = "Sign off project checklist", description = "An approver — administrator, CISO, security "
            + "champion — signs a submitted revision off at the edition read. With four-eyes approval on, not one of its "
            + "authors. The lines bound to a rule are measured again, and the sign-off is refused when one's outcome "
            + "or reason is not what the submission stored; accepted, the measurements are frozen with it. 403 for "
            + "another role; 409 checklist-not-submitted, checklist-changed, checklist-four-eyes, checklist-incomplete "
            + "(a proof lapsed since the submission), checklist-measurement-changed (a measurement changed since the "
            + "submission) — their lines in the problem's lines member.")
    // Declaring the 409 drops the 200 springdoc would infer, so it is declared too, as it was inferred.
    @ApiResponse(responseCode = "200", description = "OK",
            content = @Content(mediaType = "*/*", schema = @Schema(implementation = ChecklistView.class)))
    @ApiResponse(responseCode = "409", description = "The revision cannot be signed off; checklist-incomplete and "
            + "checklist-measurement-changed name their lines",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(oneOf = {
                    ChecklistRefusals.Incomplete.class, ChecklistRefusals.Measured.class})))
    @PostMapping("/{revision}/sign-off")
    @RequiresWriteAccount
    public ChecklistView signOff(
            @PathVariable long projectId,
            @PathVariable int revision,
            @RequestBody ChecklistEditionRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.signOff(projectId, revision, allowanceOf(principal), body == null ? null : body.edition(),
                participant(principal, request));
    }

    @Operation(summary = "Reopen project checklist", description = "The next revision of a signed-off one, on the same "
            + "version, every answer and proof carried as current; the signed revision is never modified. 409 "
            + "checklist-not-signed-off, checklist-not-latest, checklist-changed.")
    @PostMapping("/{revision}/reopen")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresWriteAccount
    public ChecklistView reopen(
            @PathVariable long projectId,
            @PathVariable int revision,
            @RequestBody ChecklistEditionRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return checklists.reopen(projectId, revision, allowanceOf(principal), body == null ? null : body.edition(),
                participant(principal, request));
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
