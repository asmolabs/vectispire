package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.access.VisibleProject;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.checklists.AnswerWords;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistAnswer;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistLayout;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistRenderer;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistStatement;
import com.asmolabs.vectispire.common.domain.checklists.DocumentZip;
import com.asmolabs.vectispire.common.domain.checklists.Measurement;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementOutcome;
import com.asmolabs.vectispire.common.domain.checklists.NoDataReason;
import com.asmolabs.vectispire.common.domain.checklists.Reconciliation;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.checklists.internal.StoredForms;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistDocumentEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistDocumentRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEvidenceEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEvidenceRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionRepository;
import com.asmolabs.vectispire.core.crypto.SigningKeyService;
import com.asmolabs.vectispire.core.settings.ProductVersion;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * A revision's document: the organisation's workbook filled in, the same statement as {@code checklist.json},
 * and — once signed off — their detached signatures (decision 0032 §10).
 *
 * <h2>Signed inside the sign-off, served as stored</h2>
 *
 * <p>A signed-off revision's package is rendered and signed <b>in the sign-off's own transaction</b> and
 * stored in {@code t_checklist_document}: the route serves those bytes, so that the document an auditor
 * receives next year is the one that was signed, whatever the product version, the renderer or the
 * signing key has become since. Rendering it again on each download would sign today's reading of the
 * rows with today's code, and call it the sign-off's.
 *
 * <p>A draft, a submitted or a superseded revision renders on request, <b>unsigned</b>, its measured lines
 * measured for the rendering (a superseded one's the last stored), and its {@code Evidence} sheet opening
 * with {@value ChecklistRenderer#DRAFT_BANNER}. No signature: the platform's key attests to what somebody
 * signed off, never to a picture of work in progress. A revision signed off before documents were signed
 * has no stored package either; it renders the same way, unsigned, and its first line says so.
 *
 * <h2>The whole project, or nothing</h2>
 *
 * <p>The export refuses the project here, like every other checklist read (§8): absent, hidden and seen in
 * part are one "Project not found." An integration key restricted to one repository never sees a whole
 * project, so the export route that accepts one answers it 404.
 */
@Service
public class ChecklistDocumentService {

    static final String WORKBOOK = "checklist.xlsx";
    static final String STATEMENT = "checklist.json";
    static final String SIGNATURE = ".sig";

    /** Column {@code t_checklist_document.product_version}. */
    private static final int MAX_PRODUCT_VERSION = 100;

    private final ChecklistRepository checklists;
    private final ChecklistAnswerRepository answers;
    private final ChecklistEvidenceRepository evidence;
    private final ChecklistItemRepository items;
    private final ChecklistTemplateRepository templates;
    private final ChecklistTemplateVersionRepository versions;
    private final ChecklistMeasurementRepository measurements;
    private final ChecklistDocumentRepository documents;
    private final StoredForms forms;
    private final ChecklistMeasurer measurer;
    private final SolutionQueryService projects;
    private final SigningKeyService signing;
    private final ProductVersion productVersion;
    private final ObjectMapper json;
    private final AuditLogService audit;
    private final Clock clock;

    public ChecklistDocumentService(
            ChecklistRepository checklists,
            ChecklistAnswerRepository answers,
            ChecklistEvidenceRepository evidence,
            ChecklistItemRepository items,
            ChecklistTemplateRepository templates,
            ChecklistTemplateVersionRepository versions,
            ChecklistMeasurementRepository measurements,
            ChecklistDocumentRepository documents,
            StoredForms forms,
            ChecklistMeasurer measurer,
            SolutionQueryService projects,
            SigningKeyService signing,
            ProductVersion productVersion,
            ObjectMapper json,
            AuditLogService audit,
            Clock clock) {
        this.checklists = checklists;
        this.answers = answers;
        this.evidence = evidence;
        this.items = items;
        this.templates = templates;
        this.versions = versions;
        this.measurements = measurements;
        this.documents = documents;
        this.forms = forms;
        this.measurer = measurer;
        this.projects = projects;
        this.signing = signing;
        this.productVersion = productVersion;
        this.json = json;
        this.audit = audit;
        this.clock = clock;
    }

    // ------------------------------------------------------------------ the export

    /**
     * The revision's document: the stored, signed package of a signed-off revision, or an unsigned rendering
     * of any other. Audited as {@code CHECKLIST_EXPORTED} once handed over, naming which and its digest.
     */
    public ChecklistDocumentDownload export(long projectId, int revision, VisibilityService.Allowance allowance,
            RequestActor actor) {
        Optional<SolutionQueryService.ProjectMembers> members = projects.members(projectId);
        List<Long> repositoryIds = List.copyOf(
                members.map(SolutionQueryService.ProjectMembers::repositoryIds).orElse(List.of()));
        VisibleProject project = RowVisibility.requireWhollyVisibleProject(projectId,
                members.map(SolutionQueryService.ProjectMembers::name), repositoryIds, allowance);
        ChecklistEntity checklist = checklists.findByProjectIdAndRevision(project.projectId(), revision)
                .orElseThrow(() -> new NotFoundException("Project \"" + project.name() + "\" has no checklist revision "
                        + revision + "."));

        Optional<ChecklistDocumentEntity> stored = documents.findByChecklistId(checklist.getId());
        byte[] content;
        if (stored.isPresent()) {
            content = stored.get().getContent();
        } else {
            Rendered rendered = render(project, repositoryIds, checklist, false, clock.instant());
            LinkedHashMap<String, DocumentZip.Entry> parts = new LinkedHashMap<>();
            parts.put(WORKBOOK, DocumentZip.Entry.of(rendered.workbook()));
            parts.put(STATEMENT, DocumentZip.Entry.of(rendered.statement()));
            content = DocumentZip.of(parts);
        }
        String sha256 = Digests.sha256Hex(content);
        boolean signed = stored.isPresent();

        audit.record(actor.entry(AuditOperation.CHECKLIST_EXPORTED, project.projectId() + "/" + revision,
                "Checklist of project \"" + project.name() + "\", revision " + revision + " (" + checklist.getStatus()
                        + ") downloaded: " + (signed ? "the package signed at its sign-off" : "rendered unsigned")
                        + ", SHA-256 " + sha256 + "."));
        return new ChecklistDocumentDownload("checklist-project-" + project.projectId() + "-revision-" + revision + ".zip",
                signed, sha256, content);
    }

    // ------------------------------------------------------------------ the sign-off's document

    /**
     * Loads the signing key — or creates and stores it, the first time — outside any transaction. The key's
     * first use inserts a row of its own and reads it back; inside the sign-off's transaction a lost race on
     * that insert would mark the whole sign-off for rollback, and on SQLite its read-then-write would wait
     * on this very transaction's lock. Called before the sign-off opens one, so that {@link #produceSigned}
     * finds it loaded.
     */
    void requireSigningKey() {
        signing.getKeyId();
    }

    /**
     * Renders, signs and stores a revision's document, <b>in the caller's transaction</b> — the sign-off's,
     * after its row says signed off and its measurements are stored, so that the document and the sign-off
     * commit or roll back together. Nothing leaves the process: rendering and signing are computation.
     *
     * @return the package's SHA-256, for the sign-off's audit entry
     * @throws IllegalStateException outside a transaction, or when the revision is not signed off
     */
    String produceSigned(long checklistId, VisibleProject project, List<Long> repositoryIds) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("A checklist's signed document is produced inside its sign-off's transaction.");
        }
        ChecklistEntity checklist = checklists.findById(checklistId)
                .orElseThrow(() -> new IllegalStateException("Checklist " + checklistId + " is gone."));
        if (ChecklistStatus.ofStored(checklist.getStatus()) != ChecklistStatus.SIGNED_OFF || checklist.getSignedOffAt() == null) {
            throw new IllegalStateException("Revision " + checklist.getRevision() + " is " + checklist.getStatus()
                    + ": only a signed-off revision's document is signed.");
        }
        Rendered rendered = render(project, repositoryIds, checklist, true, checklist.getSignedOffAt());
        String workbookSignature = signing.sign(rendered.workbook());
        String statementSignature = signing.sign(rendered.statement());
        LinkedHashMap<String, DocumentZip.Entry> parts = new LinkedHashMap<>();
        parts.put(WORKBOOK, DocumentZip.Entry.of(rendered.workbook()));
        parts.put(STATEMENT, DocumentZip.Entry.of(rendered.statement()));
        // The detached signatures as cosign writes them — base64 text — so that `cosign verify-blob --key
        // --signature checklist.xlsx.sig checklist.xlsx` checks them against the published public key.
        parts.put(WORKBOOK + SIGNATURE, DocumentZip.Entry.of(workbookSignature.getBytes(StandardCharsets.US_ASCII)));
        parts.put(STATEMENT + SIGNATURE, DocumentZip.Entry.of(statementSignature.getBytes(StandardCharsets.US_ASCII)));
        byte[] content = DocumentZip.of(parts);

        ChecklistDocumentEntity document = new ChecklistDocumentEntity();
        document.setChecklistId(checklist.getId());
        document.setProjectId(checklist.getProjectId());
        document.setContent(content);
        document.setSizeBytes((long) content.length);
        document.setSha256(Digests.sha256Hex(content));
        document.setWorkbookSha256(Digests.sha256Hex(rendered.workbook()));
        document.setWorkbookSignature(workbookSignature);
        document.setStatementSha256(Digests.sha256Hex(rendered.statement()));
        document.setStatementSignature(statementSignature);
        document.setSigningKeyId(signing.getKeyId());
        document.setProductVersion(Optional.ofNullable(productVersion.get())
                .map(version -> BoundedText.clip(version, MAX_PRODUCT_VERSION)).orElse(null));
        document.setProducedAt(checklist.getSignedOffAt());
        documents.save(document);
        return document.getSha256();
    }

    // ------------------------------------------------------------------ rendering

    /** The two parts of a document: the filled workbook, and the statement as {@code checklist.json}. */
    private record Rendered(byte[] workbook, byte[] statement) {}

    private Rendered render(VisibleProject project, List<Long> repositoryIds, ChecklistEntity checklist, boolean signed,
            Instant now) {
        ChecklistTemplateVersionEntity version = versions.findById(checklist.getTemplateVersionId())
                .orElseThrow(() -> new IllegalStateException("The version of checklist " + checklist.getId() + " is gone."));
        ChecklistTemplateEntity template = templates.findById(version.getTemplateId())
                .orElseThrow(() -> new IllegalStateException("Template " + version.getTemplateId() + " is gone."));
        ChecklistLayout layout = forms.layout(version.getLayout());
        ChecklistStatement statement = statement(project, repositoryIds, checklist, version, template, layout, signed, now);
        byte[] workbook = ChecklistRenderer.render(version.getSourceBytes(), layout, statement);
        byte[] text;
        try {
            // The real mapper — the one every route writes with — so that the contract is what a reader
            // receives: ISO instants, nulls written, the fields in the order the record declares.
            text = json.writerWithDefaultPrettyPrinter().writeValueAsBytes(statement);
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("A checklist statement could not be written.", impossible);
        }
        return new Rendered(workbook, text);
    }

    /** The statement of one revision: what the workbook receives, and {@code checklist.json}. */
    private ChecklistStatement statement(VisibleProject project, List<Long> repositoryIds, ChecklistEntity checklist,
            ChecklistTemplateVersionEntity version, ChecklistTemplateEntity template, ChecklistLayout layout, boolean signed,
            Instant now) {
        AnswerWords words = layout.answers();
        List<ChecklistItemEntity> lines = items.findByVersionIdOrderByPositionAsc(version.getId());
        Map<Long, List<ChecklistAnswerEntity>> given = new HashMap<>();
        answers.findByChecklistIdOrderByIdAsc(checklist.getId())
                .forEach(row -> given.computeIfAbsent(row.getItemId(), id -> new ArrayList<>()).add(row));
        Map<Long, List<ChecklistEvidenceEntity>> proofs = new HashMap<>();
        evidence.findByChecklistIdOrderByIdAsc(checklist.getId())
                .forEach(row -> proofs.computeIfAbsent(row.getItemId(), id -> new ArrayList<>()).add(row));
        Map<Long, ChecklistStatement.Measured> measured = measured(checklist, lines, repositoryIds, now);

        List<ChecklistStatement.Line> statementLines = new ArrayList<>();
        for (ChecklistItemEntity item : lines) {
            List<ChecklistStatement.Answer> history = given.getOrDefault(item.getId(), List.of()).stream()
                    .map(row -> answer(row, words)).toList();
            ChecklistStatement.Answer current = history.isEmpty() ? null : history.getLast();
            ChecklistStatement.Measured measurement = measured.get(item.getId());
            Reconciliation reconciliation = measurement == null
                    ? Reconciliation.NOT_MEASURED_HERE
                    : Reconciliation.of(Optional.ofNullable(current).map(answer -> ChecklistAnswer.parse(answer.value())),
                            MeasurementOutcome.ofStored(measurement.outcome()));
            statementLines.add(new ChecklistStatement.Line(item.getId(), item.getItemKey(), item.getPosition(),
                    item.getSheetRow(), item.getDomain(), item.getObjective(), item.getControl(), item.getContact(),
                    item.getKpi(), item.getContentDigest(), item.getEvidenceKind(), item.getEvidenceValidityMonths(), current,
                    history, measurement, reconciliation.wireName(),
                    proofs.getOrDefault(item.getId(), List.of()).stream().map(ChecklistDocumentService::proof).toList()));
        }

        // A returned revision was submitted once and is not any more: its submission is named only while it stands.
        boolean submissionStands = checklist.getSubmittedAt() != null
                && (checklist.getReturnedAt() == null || checklist.getSubmittedAt().isAfter(checklist.getReturnedAt()));
        return new ChecklistStatement(ChecklistStatement.FORM, checklist.getStatus(), signed,
                new ChecklistStatement.Project(project.projectId(), project.name()), checklist.getRevision(),
                new ChecklistStatement.Template(template.getSlug(), template.getName(), version.getOrdinal(),
                        version.getLabel(), version.getSourceSha256()),
                new ChecklistStatement.Header(project.name(), checklist.getAuthor(), checklist.getSignedOffAt()),
                new ChecklistStatement.Act(checklist.getOpenedBy(), checklist.getOpenedAt()),
                submissionStands ? new ChecklistStatement.Act(checklist.getSubmittedBy(), checklist.getSubmittedAt()) : null,
                checklist.getSignedOffAt() == null ? null
                        : new ChecklistStatement.Act(checklist.getSignedOffBy(), checklist.getSignedOffAt()),
                checklist.getSignOffFourEyes(), productVersion.get(), now, statementLines);
    }

    /**
     * Each measured line's measurement, as {@code ProjectChecklistService.measurements} shows it: what the
     * sign-off froze for a signed-off revision; for a draft or a submitted one what the rules find now,
     * computed for this rendering and stored nowhere; for a superseded one the last stored, its rules not
     * applied again to data that has moved on since.
     */
    private Map<Long, ChecklistStatement.Measured> measured(ChecklistEntity checklist, List<ChecklistItemEntity> lines,
            List<Long> repositoryIds, Instant now) {
        Map<Long, ChecklistStatement.Measured> measured = new HashMap<>();
        ChecklistStatus status = ChecklistStatus.ofStored(checklist.getStatus());
        if (status == ChecklistStatus.DRAFT || status == ChecklistStatus.SUBMITTED) {
            for (ChecklistMeasurer.LineMeasurement line : measurer.measure(repositoryIds, lines, now)) {
                Measurement found = line.measurement();
                measured.put(line.item().getId(), new ChecklistStatement.Measured(MeasurementPurpose.READ.wireName(),
                        line.rule().kind().wireName(), line.rule().digest(), line.rule().canonical(),
                        found.outcome().wireName(), found.reason().map(NoDataReason::wireName).orElse(null),
                        found.asOf().orElse(null), now, found.summary(), found.evidenceDigest(), found.evidenceJson()));
            }
            return measured;
        }
        Map<Long, ChecklistMeasurementEntity> stored = new HashMap<>();
        measurements.findByChecklistIdAndPurposeOrderByIdAsc(checklist.getId(), MeasurementPurpose.SUBMISSION.wireName())
                .forEach(row -> stored.put(row.getItemId(), row));
        measurements.findByChecklistIdAndPurposeOrderByIdAsc(checklist.getId(), MeasurementPurpose.SIGN_OFF.wireName())
                .forEach(row -> stored.put(row.getItemId(), row));
        stored.forEach((itemId, row) -> measured.put(itemId, new ChecklistStatement.Measured(row.getPurpose(),
                row.getRuleKind(), row.getRuleDigest(), row.getBoundRule(), row.getOutcome(), row.getReason(), row.getAsOf(),
                row.getComputedAt(), Measurement.read(row.getEvidence()).summary(), row.getEvidenceDigest(),
                row.getEvidence())));
        return measured;
    }

    private static ChecklistStatement.Answer answer(ChecklistAnswerEntity row, AnswerWords words) {
        return new ChecklistStatement.Answer(row.getId(), row.getValue(), words.written(ChecklistAnswer.parse(row.getValue())),
                row.getComment(), row.getAnsweredBy(), row.getAnsweredAt(), row.getCarriedFromId(), row.getCarriedBy(),
                row.getCarriedAt(), row.isNeedsConfirmation());
    }

    private static ChecklistStatement.Proof proof(ChecklistEvidenceEntity row) {
        return new ChecklistStatement.Proof(row.getId(), row.getKind(), row.getLink(), row.getFileName(), row.getMediaType(),
                row.getFileSize(), row.getFileSha256(), dayOf(row.getPerformedOn()),
                row.getValidUntil() == null ? null : dayOf(row.getValidUntil()), row.getAddedBy(), row.getAddedAt(),
                row.getWithdrawnBy(), row.getWithdrawnAt());
    }

    private static LocalDate dayOf(Instant instant) {
        return LocalDate.ofInstant(instant, ZoneOffset.UTC);
    }
}
