package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.access.VisibleProject;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.checklists.AnswerWords;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistAnswer;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistItem;
import com.asmolabs.vectispire.common.domain.checklists.EvidenceRequirement;
import com.asmolabs.vectispire.common.domain.checklists.GivenAnswer;
import com.asmolabs.vectispire.common.domain.checklists.Measurement;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementOutcome;
import com.asmolabs.vectispire.common.domain.checklists.NoDataReason;
import com.asmolabs.vectispire.common.domain.checklists.Reconciliation;
import com.asmolabs.vectispire.common.domain.checklists.VersionPairing;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.checklists.ChecklistConflict.Cause;
import com.asmolabs.vectispire.core.checklists.internal.StoredForms;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEvidenceEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEvidenceRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistFileEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistFileRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.IntConsumer;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.unit.DataSize;

/**
 * A project's checklists, answered by people (decision 0032 §4, §5, §8).
 *
 * <h2>The whole project, or nothing</h2>
 *
 * <p>Every method names a project and refuses it first, here, through {@link
 * RowVisibility#requireWhollyVisibleProject}: a project that does not exist, one the caller sees
 * nothing of and one it sees only part of are all "Project not found." (404, never 403 — open
 * question 5). The routes hand the caller's allowance on and decide nothing; whoever calls these
 * methods next — a route, a task, a neighbouring service — is refused the same.
 *
 * <h2>What a person has read is what is changed</h2>
 *
 * <p>A revision counts its writes, its {@code edition}, and every write names the edition the person
 * read on screen: absent is 400, and a revision changed since is 409. The template lot learned why:
 * a conditional statement on the edition the request itself had just read only orders two requests,
 * and lets one person's work silently replace another's. Two grains:
 *
 * <ul>
 *   <li><b>A line's writes</b> — an answer, a confirmation, a proof, its withdrawal — are refused when
 *       <em>that line</em> changed since the edition named ({@code checklist-line-changed}), not when
 *       another line did: a team fills one checklist together, and refusing every answer after the
 *       first would have them reload for each other's lines. What one line can lose to another
 *       person's write is its own answer or proof, and that is what the comparison sees;
 *   <li><b>A revision's transitions</b> — submitting, returning, signing off, reopening, moving to
 *       another version — are refused when <em>anything</em> changed since ({@code checklist-changed}):
 *       what is submitted or signed off is what the person reviewed, line for line.
 * </ul>
 *
 * <p>Each write is then one conditional statement on the edition this request read, whose row count
 * says whether another write came first; if one did, the request reads again and decides again,
 * a few times, before answering 409.
 *
 * <h2>Answers are never rewritten</h2>
 *
 * <p>Answering inserts a row; the current answer is the newest per line and the history is every row,
 * each with its author — the principal, never a name from the body — and its instant. Moving to
 * another version or reopening opens a new revision and <b>carries</b> answers into it (§4): each copy
 * is a new row pointing at the one it came from, keeping its author and instant, naming who carried
 * it. An unchanged line's answer is carried as current; a changed one's — the wording, the KPI, the
 * evidence or the binding moved, or the item was paired by hand — waits for somebody to answer or
 * confirm it, and so does a "not applicable" carried onto a version that does not offer it. Nothing is
 * carried between two templates: the same words in another organisation's checklist are another
 * question. The proofs follow their answers, re-dated against the new line's validity.
 *
 * <h2>Sign-off and four-eyes</h2>
 *
 * <p>Signing off is an approver's — {@code canApproveTriage}: an administrator, a CISO, a security
 * champion — refused 403 to anybody else before anything is read, the governor included, who decides
 * the rules and takes no decision under them. With {@code FOUR_EYES_APPROVAL_REQUIRED} on (open
 * question 2), the signer is <b>none of the revision's authors</b>: whoever opened a fresh checklist,
 * gave an answer it holds, confirmed a carried line, attached or withdrew a proof, or submitted it —
 * carrying answers over is not writing (see {@code authorsOf}) — compared as two people,
 * the account and its name, like the template versions' publisher. The ADR names the submitter; an
 * answerer is as much the revision's author, and signing one's own answers is what four-eyes exists to
 * stop. The refusal is audited and signalled ({@code VECTI-SEC-026}), and so is a sign-off refused
 * because a proof stopped holding since the submission.
 *
 * <h2>Measured lines (§6)</h2>
 *
 * <p>A line bound to a rule is measured by {@link ChecklistMeasurer} over exactly the repositories the
 * whole-project guard judged the caller by. <b>Vectispire never answers</b>: a measurement is evidence
 * beside a person's answer. It is computed for a reader and stored nowhere, and stored when something
 * relies on it — an answer resting on the measurement its person read, the submission, the sign-off —
 * each time applied again, since freshness is judged at every step that relies on it. A "yes" against
 * a failure is refused at submission (question 3); a "yes" where there is no data needs its comment
 * and a proof (question 4); a sign-off whose measurement is no longer what the submission stored is
 * refused, and an accepted one freezes the revision's measurements with it.
 *
 * <p><b>Every write is audited after its transaction commits</b> — the audit log opens its own, and
 * on SQLite would wait on this one's file lock.
 */
@Service
public class ProjectChecklistService {

    /** Bounded before the write, like an answer's comment (decision 0032 §2). */
    static final int MAX_REASON = 4_000;

    static final int MAX_LINK = 2_000;

    /** Column {@code t_checklist_evidence.file_name} and {@code media_type}. */
    static final int MAX_FILE_NAME = 255;

    static final int MAX_MEDIA_TYPE = 255;

    /** How many times a write reads again after another write came first, before answering 409. */
    private static final int ATTEMPTS = 3;

    /** No proof is dated before this: a day earlier is a typing mistake, not a penetration test. */
    private static final LocalDate EARLIEST_PROOF = LocalDate.of(1970, 1, 1);

    private final ChecklistRepository checklists;
    private final ChecklistAnswerRepository answers;
    private final ChecklistEvidenceRepository evidence;
    private final ChecklistFileRepository files;
    private final ChecklistTemplateRepository templates;
    private final ChecklistTemplateVersionRepository versions;
    private final ChecklistItemRepository items;
    private final ChecklistMeasurementRepository measurements;
    private final StoredForms forms;
    private final ChecklistMeasurer measurer;
    private final SolutionQueryService projects;
    private final SettingsService settings;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final long maxFileBytes;

    public ProjectChecklistService(
            ChecklistRepository checklists,
            ChecklistAnswerRepository answers,
            ChecklistEvidenceRepository evidence,
            ChecklistFileRepository files,
            ChecklistTemplateRepository templates,
            ChecklistTemplateVersionRepository versions,
            ChecklistItemRepository items,
            ChecklistMeasurementRepository measurements,
            StoredForms forms,
            ChecklistMeasurer measurer,
            SolutionQueryService projects,
            SettingsService settings,
            AuditLogService audit,
            TransactionTemplate transactions,
            Clock clock,
            @Value("${vectispire.http.max-body.checklist-evidence:25MB}") DataSize maxFile) {
        this.checklists = checklists;
        this.answers = answers;
        this.evidence = evidence;
        this.files = files;
        this.templates = templates;
        this.versions = versions;
        this.items = items;
        this.measurements = measurements;
        this.forms = forms;
        this.measurer = measurer;
        this.projects = projects;
        this.settings = settings;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
        this.maxFileBytes = maxFile.toBytes();
    }

    /**
     * Who is acting: the signed-in account — never a name taken from the request — and the actor the
     * audit entry names.
     */
    public record Participant(UserView user, RequestActor actor) {

        long accountId() {
            return user.id();
        }

        String username() {
            return user.username();
        }

        Optional<Role> role() {
            return Role.of(user.role());
        }
    }

    /** Somebody who wrote a revision: the account, and the name it wrote under. */
    private record Author(long accountId, String username) {}

    // ------------------------------------------------------------------ reads

    /** The project's revisions, newest first. */
    public List<ChecklistRevisionSummary> list(long projectId, VisibilityService.Allowance allowance) {
        VisibleProject project = requireProject(projectId, allowance);
        List<ChecklistEntity> rows = checklists.findByProjectIdOrderByRevisionDesc(project.projectId());
        Map<Long, Integer> revisionOf = rows.stream()
                .collect(Collectors.toMap(ChecklistEntity::getId, ChecklistEntity::getRevision));
        Map<Long, VersionRef> refs = new HashMap<>();
        return rows.stream()
                .map(row -> summary(row, refs.computeIfAbsent(row.getTemplateVersionId(), this::versionRef), revisionOf))
                .toList();
    }

    /**
     * The project's name and its newest revision — what the page shows before a checklist exists —
     * behind the same whole-project guard as every other read: a caller who sees part of the project
     * learns not even its name.
     */
    public ChecklistProjectContext context(long projectId, VisibilityService.Allowance allowance) {
        VisibleProject project = requireProject(projectId, allowance);
        Optional<ChecklistEntity> latest = checklists.findFirstByProjectIdOrderByRevisionDesc(project.projectId());
        return new ChecklistProjectContext(project.projectId(), project.name(),
                latest.map(ChecklistEntity::getRevision).orElse(null), latest.map(ChecklistEntity::getEdition).orElse(null));
    }

    /** The published versions a checklist may be opened on, by template slug then number. */
    public List<ChecklistOfferedVersion> offered(long projectId, VisibilityService.Allowance allowance) {
        requireProject(projectId, allowance);
        List<ChecklistOfferedVersion> offered = new ArrayList<>();
        for (ChecklistTemplateEntity template : templates.findAllByOrderBySlugAsc()) {
            versions.summariesOf(template.getId()).stream()
                    .filter(version -> TemplateVersionStatus.PUBLISHED.wireName().equals(version.status()))
                    .forEach(version -> offered.add(new ChecklistOfferedVersion(template.getSlug(), template.getName(),
                            version.ordinal(), version.label(), version.itemCount() == null ? 0 : version.itemCount(),
                            version.offersNotApplicable(), version.publishedAt())));
        }
        return offered;
    }

    public ChecklistView read(long projectId, int revision, VisibilityService.Allowance allowance) {
        VisibleProject project = requireProject(projectId, allowance);
        return view(project, requireRevision(project, revision));
    }

    /** Every answer and every proof of one line, oldest first. */
    public ChecklistLineHistory history(long projectId, int revision, long itemId, VisibilityService.Allowance allowance) {
        VisibleProject project = requireProject(projectId, allowance);
        ChecklistEntity checklist = requireRevision(project, revision);
        ChecklistItemEntity item = requireLine(checklist, itemId);
        LocalDate today = today();
        return new ChecklistLineHistory(project.projectId(), checklist.getRevision(), item.getId(),
                answers.findByChecklistIdAndItemIdOrderByIdAsc(checklist.getId(), item.getId()).stream()
                        .map(ChecklistAnswerView::of).toList(),
                evidence.findByChecklistIdAndItemIdOrderByIdAsc(checklist.getId(), item.getId()).stream()
                        .map(row -> evidenceView(row, today)).toList());
    }

    /** An uploaded proof's bytes, withdrawn or not: a withdrawal is dated, the proof stays readable. */
    public ChecklistEvidenceDownload download(
            long projectId, int revision, long evidenceId, VisibilityService.Allowance allowance) {
        VisibleProject project = requireProject(projectId, allowance);
        ChecklistEntity checklist = requireRevision(project, revision);
        ChecklistEvidenceEntity proof = requireEvidence(checklist, evidenceId);
        if (proof.getFileId() == null) {
            throw new NotFoundException("Proof " + evidenceId + " is a link, not a file: it has nothing to download.");
        }
        ChecklistFileEntity file = files.findById(proof.getFileId())
                .orElseThrow(() -> new IllegalStateException("The file of proof " + evidenceId + " is gone."));
        return new ChecklistEvidenceDownload(proof.getFileName(), file.getSha256(), file.getContent());
    }

    // ------------------------------------------------------------------ opening, moving, reopening

    /**
     * Opens the project's checklist on a published version — its first, or the next revision, moved
     * from the newest one with its answers carried (§4).
     *
     * @param seenEdition the edition of the project's newest revision the person read; null when they
     *     saw no checklist on the project. A checklist opened or changed since is refused, so that
     *     nobody moves a checklist they have not seen, nor two people open one each
     * @throws ChecklistConflict {@code checklist-version-not-published}, {@code checklist-changed},
     *     {@code checklist-same-version}
     */
    public ChecklistView open(long projectId, VisibilityService.Allowance allowance, String templateSlug,
            Integer versionOrdinal, Integer seenEdition, Participant who) {
        VisibleProject project = requireProject(projectId, allowance);
        if (templateSlug == null || templateSlug.isBlank() || versionOrdinal == null) {
            throw new InvalidInputException("Name the template (\"template\", its slug) and its version (\"version\", "
                    + "its number) to open the checklist on.");
        }
        ChecklistTemplateEntity template = templates.findBySlug(templateSlug.strip())
                .orElseThrow(() -> new NotFoundException("No checklist template \""
                        + BoundedText.clip(templateSlug.strip(), 70) + "\"."));
        ChecklistTemplateVersionEntity version = versions.findByTemplateIdAndOrdinal(template.getId(), versionOrdinal)
                .orElseThrow(() -> new NotFoundException("Checklist template \"" + template.getSlug()
                        + "\" has no version " + versionOrdinal + "."));
        if (TemplateVersionStatus.ofStored(version.getStatus()) != TemplateVersionStatus.PUBLISHED) {
            throw new ChecklistConflict(Cause.VERSION_NOT_PUBLISHED, "Version " + versionOrdinal + " of \""
                    + template.getSlug() + "\" is " + version.getStatus() + ": a checklist opens on a published version.");
        }

        Optional<ChecklistEntity> latest = checklists.findFirstByProjectIdOrderByRevisionDesc(project.projectId());
        if (latest.isEmpty()) {
            if (seenEdition != null) {
                throw new ChecklistConflict(Cause.CHANGED, "The project has no checklist any more: read it again.");
            }
        } else {
            ChecklistEntity previous = latest.get();
            if (seenEdition == null) {
                throw new ChecklistConflict(Cause.CHANGED, "The project already has a checklist — revision "
                        + previous.getRevision() + ", " + previous.getStatus() + ", opened since you read it. Read it "
                        + "again; moving it to another version names the edition you read.");
            }
            requireSeen(previous, seenEdition, "moving it to another version");
            if (previous.getTemplateVersionId().equals(version.getId())) {
                throw new ChecklistConflict(Cause.SAME_VERSION, "Revision " + previous.getRevision()
                        + " is already on version " + versionOrdinal + " of \"" + template.getSlug() + "\""
                        + (ChecklistStatus.ofStored(previous.getStatus()) == ChecklistStatus.SIGNED_OFF
                                ? ": reopen it for a new revision on the same version."
                                : "."));
            }
        }

        Carried carried = latest.map(previous -> carryOnto(previous, version, template)).orElse(Carried.NOTHING);
        ChecklistEntity opened = openRevision(project, version, latest, carried, who);

        boolean moved = latest.isPresent();
        String line = moved
                ? "Checklist of project \"" + project.name() + "\": revision " + opened.getRevision()
                        + " opened on version " + versionOrdinal + " of \"" + template.getSlug() + "\", moved from revision "
                        + latest.get().getRevision() + carried.describe()
                : "Checklist of project \"" + project.name() + "\" opened on version " + versionOrdinal + " of \""
                        + template.getSlug() + "\", revision " + opened.getRevision() + ".";
        audit.record(who.actor().entry(moved ? AuditOperation.CHECKLIST_MOVED_TO_VERSION : AuditOperation.CHECKLIST_OPENED,
                resource(project, opened.getRevision()), line));
        return view(project, opened);
    }

    /**
     * Opens the next revision of a signed-off one, on the same version, every answer and proof carried
     * as current — nothing to confirm, since no line changed. The signed revision is never modified.
     *
     * @throws ChecklistConflict {@code checklist-not-signed-off}, {@code checklist-not-latest}, {@code
     *     checklist-changed}
     */
    public ChecklistView reopen(long projectId, int revision, VisibilityService.Allowance allowance, Integer seenEdition,
            Participant who) {
        VisibleProject project = requireProject(projectId, allowance);
        ChecklistEntity signed = requireRevision(project, revision);
        requireEdition(seenEdition);
        if (ChecklistStatus.ofStored(signed.getStatus()) != ChecklistStatus.SIGNED_OFF) {
            throw new ChecklistConflict(Cause.NOT_SIGNED_OFF, "Revision " + revision + " is " + signed.getStatus()
                    + ": only a signed-off revision is reopened.");
        }
        requireLatest(project, signed);
        requireSeen(signed, seenEdition, "reopening it");
        ChecklistTemplateVersionEntity version = versions.findById(signed.getTemplateVersionId())
                .orElseThrow(() -> new IllegalStateException("The version of checklist " + signed.getId() + " is gone."));
        ChecklistTemplateEntity template = templateOf(version);

        Carried carried = carryOnto(signed, version, template);
        ChecklistEntity opened = openRevision(project, version, Optional.of(signed), carried, who);

        audit.record(who.actor().entry(AuditOperation.CHECKLIST_REOPENED, resource(project, opened.getRevision()),
                "Checklist of project \"" + project.name() + "\": signed-off revision " + revision + " reopened as revision "
                        + opened.getRevision() + " on the same version" + carried.describe()));
        return view(project, opened);
    }

    // ------------------------------------------------------------------ answering

    /**
     * Answers a line of a draft: a new row of its history, the principal its author.
     *
     * <p><b>Resting on a measurement</b> — the one click a measured line offers (decision 0032 §6): the
     * person names the measurement they read, by its {@code evidenceDigest}, and the line's rule is
     * applied again now. The same evidence, and the answer is stored resting on that measurement, which
     * is stored with it; other evidence, and the answer is refused — the person would be accepting a
     * finding they never saw. The value stays the person's: Vectispire never answers, and a "yes"
     * against a failure is the submission's to refuse, not this.
     *
     * @param measurementDigest the {@code evidenceDigest} of the measurement the person read, to rest the
     *     answer on it; null or blank for an answer resting on none
     * @param seenEdition the edition the person read — the line changed since is refused
     * @throws InvalidInputException no edition, an answer that is none, a negative one without its
     *     comment, "not applicable" on a version that does not offer it, a measurement named on a line
     *     bound to no rule (400)
     * @throws ChecklistConflict {@code checklist-not-draft}, {@code checklist-line-changed}, {@code
     *     checklist-changed}, {@code checklist-measurement-changed}
     */
    public ChecklistView answer(long projectId, int revision, long itemId, VisibilityService.Allowance allowance,
            String value, String comment, String measurementDigest, Integer seenEdition, Participant who) {
        Guarded guarded = requireWhole(projectId, allowance);
        VisibleProject project = guarded.project();
        ChecklistEntity checklist = requireRevision(project, revision);
        requireEdition(seenEdition);
        ChecklistItemEntity item = requireLine(checklist, itemId);
        GivenAnswer given = GivenAnswer.of(ChecklistAnswer.parse(value), comment, wordsOf(checklist));
        Instant now = clock.instant();
        Optional<ChecklistMeasurer.LineMeasurement> resting = restingOn(guarded, checklist, item, measurementDigest, now);

        ChecklistEntity written = writeLine(checklist, item.getId(), seenEdition, edition -> {
            ChecklistAnswerEntity row = answerRow(checklist.getId(), item.getId(), given.value().wireName(),
                    given.comment().orElse(null), who, now, null, edition);
            resting.ifPresent(measured -> row.setMeasurementId(measurements.save(measurementRow(checklist.getId(),
                    measured, MeasurementPurpose.ANSWER, now, who, null, Optional.of(given.value()))).getId()));
            answers.save(row);
        });

        audit.record(who.actor().entry(AuditOperation.CHECKLIST_ANSWERED, resource(project, revision),
                "Checklist of project \"" + project.name() + "\", revision " + revision + ", line " + item.getPosition()
                        + " (row " + item.getSheetRow() + "): answered " + given.value().wireName()
                        + given.comment().map(text -> ", with a comment of " + text.length() + " characters").orElse("")
                        + resting.map(measured -> ", resting on its measurement — "
                                + measured.measurement().outcome().wireName()
                                + measured.measurement().reason().map(reason -> " (" + reason.wireName() + ")").orElse("")
                                + ", evidence sha256 " + measured.measurement().evidenceDigest().substring(0, 12))
                                .orElse("")
                        + "."));
        return view(project, written);
    }

    /**
     * The measurement an answer rests on: the line's rule applied now, refused unless it judged the
     * evidence the person read.
     */
    private Optional<ChecklistMeasurer.LineMeasurement> restingOn(Guarded guarded, ChecklistEntity checklist,
            ChecklistItemEntity item, String measurementDigest, Instant now) {
        if (measurementDigest == null || measurementDigest.isBlank()) {
            return Optional.empty();
        }
        if (item.getBoundRule() == null) {
            throw new InvalidInputException("Line " + item.getPosition() + " is measured by no rule: an answer cannot "
                    + "rest on a measurement it does not have.");
        }
        ChecklistMeasurer.LineMeasurement measured = measurer.measure(guarded.repositoryIds(), item, now);
        if (!measured.measurement().evidenceDigest().equals(measurementDigest.strip())) {
            Optional<ChecklistAnswerEntity> current = currentAnswer(checklist.getId(), item.getId());
            throw ChecklistConflict.measured(Cause.MEASUREMENT_CHANGED, "The measurement of line " + item.getPosition()
                    + " is not the one you read: it is now " + describe(measured.measurement()) + ". Read it again.",
                    List.of(measuredLine(item, current, measured.measurement(), null)));
        }
        return Optional.of(measured);
    }

    /**
     * Confirms an answer carried onto a line that changed: the confirmer states it still holds, and a
     * new row says so under their name.
     *
     * @throws ChecklistConflict {@code checklist-nothing-to-confirm} when the line's answer is not one
     *     awaiting confirmation, and the causes of {@link #answer}
     */
    public ChecklistView confirm(long projectId, int revision, long itemId, VisibilityService.Allowance allowance,
            Integer seenEdition, Participant who) {
        VisibleProject project = requireProject(projectId, allowance);
        ChecklistEntity checklist = requireRevision(project, revision);
        requireEdition(seenEdition);
        ChecklistItemEntity item = requireLine(checklist, itemId);
        AnswerWords words = wordsOf(checklist);
        Instant now = clock.instant();
        record Confirmed(ChecklistAnswerEntity carried, GivenAnswer given) {}
        List<Confirmed> confirmed = new ArrayList<>(1);

        ChecklistEntity written = writeLine(checklist, item.getId(), seenEdition, edition -> {
            ChecklistAnswerEntity carried = currentAnswer(checklist.getId(), item.getId())
                    .filter(ChecklistAnswerEntity::isNeedsConfirmation)
                    .orElseThrow(() -> new ChecklistConflict(Cause.NOTHING_TO_CONFIRM, "Line " + item.getPosition()
                            + " has no carried answer awaiting confirmation."));
            // Checked again under the new version's words: a "not applicable" it does not offer is answered
            // again, never confirmed into the revision.
            GivenAnswer given = GivenAnswer.of(ChecklistAnswer.parse(carried.getValue()), carried.getComment(), words);
            answers.save(answerRow(checklist.getId(), item.getId(), given.value().wireName(), given.comment().orElse(null),
                    who, now, carried.getId(), edition));
            confirmed.add(new Confirmed(carried, given));
        });

        audit.record(who.actor().entry(AuditOperation.CHECKLIST_ANSWERED, resource(project, revision),
                "Checklist of project \"" + project.name() + "\", revision " + revision + ", line " + item.getPosition()
                        + " (row " + item.getSheetRow() + "): the answer " + confirmed.getFirst().given().value().wireName()
                        + " carried from " + confirmed.getFirst().carried().getAnsweredBy() + " confirmed."));
        return view(project, written);
    }

    // ------------------------------------------------------------------ evidence

    /**
     * Attaches a link to a line: {@code https:} or {@code http:}, at most {@value #MAX_LINK} characters.
     *
     * @param performedOn the day the work was done, {@code yyyy-MM-dd}, not in the future
     */
    public ChecklistView attachLink(long projectId, int revision, long itemId, VisibilityService.Allowance allowance,
            String link, String performedOn, Integer seenEdition, Participant who) {
        VisibleProject project = requireProject(projectId, allowance);
        ChecklistEntity checklist = requireRevision(project, revision);
        requireEdition(seenEdition);
        ChecklistItemEntity item = requireLine(checklist, itemId);
        String url = requireLink(link);
        LocalDate performed = requireDay(performedOn);
        Instant now = clock.instant();

        ChecklistEntity written = writeLine(checklist, item.getId(), seenEdition, edition -> {
            ChecklistEvidenceEntity row = proofRow(checklist, item, performed, who, now, edition);
            row.setKind("link");
            row.setLink(url);
            evidence.save(row);
        });

        audit.record(who.actor().entry(AuditOperation.CHECKLIST_EVIDENCE_ADDED, resource(project, revision),
                "Checklist of project \"" + project.name() + "\", revision " + revision + ", line " + item.getPosition()
                        + ": a link attached as proof, performed on " + performed + " — " + BoundedText.clip(url, 200)));
        return view(project, written);
    }

    /**
     * Attaches a file to a line: at most the evidence ceiling, stored apart, served back only as a
     * download.
     *
     * @param mediaType as the uploader declared it — stored and shown, never used to serve the file
     */
    public ChecklistView attachFile(long projectId, int revision, long itemId, VisibilityService.Allowance allowance,
            String fileName, String mediaType, String performedOn, byte[] content, Integer seenEdition, Participant who) {
        VisibleProject project = requireProject(projectId, allowance);
        ChecklistEntity checklist = requireRevision(project, revision);
        requireEdition(seenEdition);
        ChecklistItemEntity item = requireLine(checklist, itemId);
        String name = requireFileName(fileName);
        String type = mediaType == null || mediaType.isBlank()
                ? "application/octet-stream"
                : BoundedText.optional(mediaType.strip(), MAX_MEDIA_TYPE, "The media type");
        LocalDate performed = requireDay(performedOn);
        if (content == null || content.length == 0) {
            throw new InvalidInputException("The body is the proof's file, and it is empty.");
        }
        if (content.length > maxFileBytes) {
            throw new ChecklistFileTooLargeException(maxFileBytes);
        }
        String sha256 = Digests.sha256Hex(content);
        Instant now = clock.instant();

        ChecklistEntity written = writeLine(checklist, item.getId(), seenEdition, edition -> {
            ChecklistFileEntity file = new ChecklistFileEntity();
            file.setProjectId(project.projectId());
            file.setSha256(sha256);
            file.setSizeBytes((long) content.length);
            file.setContent(content);
            ChecklistFileEntity stored = files.save(file);
            ChecklistEvidenceEntity row = proofRow(checklist, item, performed, who, now, edition);
            row.setKind("file");
            row.setFileId(stored.getId());
            row.setFileName(name);
            row.setMediaType(type);
            row.setFileSize((long) content.length);
            row.setFileSha256(sha256);
            evidence.save(row);
        });

        audit.record(who.actor().entry(AuditOperation.CHECKLIST_EVIDENCE_ADDED, resource(project, revision),
                "Checklist of project \"" + project.name() + "\", revision " + revision + ", line " + item.getPosition()
                        + ": the file \"" + BoundedText.clip(name, 100) + "\" attached as proof, " + content.length
                        + " bytes, sha256 " + sha256 + ", performed on " + performed + "."));
        return view(project, written);
    }

    /** Withdraws a proof from a draft's line. The row stays, dated and attributed. */
    public ChecklistView withdraw(long projectId, int revision, long evidenceId, VisibilityService.Allowance allowance,
            Integer seenEdition, Participant who) {
        VisibleProject project = requireProject(projectId, allowance);
        ChecklistEntity checklist = requireRevision(project, revision);
        requireEdition(seenEdition);
        ChecklistEvidenceEntity proof = requireEvidence(checklist, evidenceId);
        if (proof.getWithdrawnAt() != null) {
            throw new ChecklistConflict(Cause.EVIDENCE_WITHDRAWN, "Proof " + evidenceId + " was withdrawn by "
                    + proof.getWithdrawnBy() + " on " + proof.getWithdrawnAt() + ".");
        }
        Instant now = clock.instant();

        ChecklistEntity written = writeLine(checklist, proof.getItemId(), seenEdition, edition -> {
            if (evidence.withdraw(proof.getId(), now, who.username(), who.accountId(), edition) != 1) {
                throw new ChecklistConflict(Cause.EVIDENCE_WITHDRAWN, "Proof " + evidenceId
                        + " was withdrawn by somebody else meanwhile.");
            }
        });

        audit.record(who.actor().entry(AuditOperation.CHECKLIST_EVIDENCE_WITHDRAWN, resource(project, revision),
                "Checklist of project \"" + project.name() + "\", revision " + revision + ": proof " + evidenceId + " ("
                        + (proof.getFileName() != null ? "the file \"" + BoundedText.clip(proof.getFileName(), 100) + "\""
                                : "a link") + ") withdrawn."));
        return view(project, written);
    }

    // ------------------------------------------------------------------ submitting, returning, signing off

    /**
     * Submits a draft for sign-off — refused while any line is unanswered, a negative answer is
     * uncommented, a proof a "yes" needs is missing or out of date, or a carried answer awaits
     * confirmation (§5).
     *
     * <p><b>The measured lines are measured again, here</b> (§6), and reconciled with their answers: a
     * "yes" against a failing measurement is refused (question 3) — a false positive is settled by
     * triage, which the figures then leave out, and a rule the organisation disagrees with is changed
     * in a new version, visibly; a "yes" where there is no data needs a comment and a proof in date
     * (question 4), which the line's problems name as for any other. The measurements are stored with
     * the submission, each with the answer it was reconciled with and what the two said together: the
     * sign-off compares its own with these.
     *
     * @throws ChecklistConflict {@code checklist-not-draft}, {@code checklist-changed}, {@code
     *     checklist-incomplete} naming the lines, {@code checklist-measurement-contradicted} naming the lines
     */
    public ChecklistView submit(long projectId, int revision, VisibilityService.Allowance allowance, Integer seenEdition,
            Participant who) {
        Guarded guarded = requireWhole(projectId, allowance);
        VisibleProject project = guarded.project();
        ChecklistEntity checklist = requireRevision(project, revision);
        requireEdition(seenEdition);
        requireStatus(checklist, ChecklistStatus.DRAFT, Cause.NOT_DRAFT, "submitted");
        requireSeen(checklist, seenEdition, "submitting it");
        Instant now = clock.instant();
        List<ChecklistMeasurer.LineMeasurement> measured = measurer.measure(guarded.repositoryIds(),
                items.findByVersionIdOrderByPositionAsc(checklist.getTemplateVersionId()), now);
        requireComplete(checklist, "submitted", outcomes(measured));
        Map<Long, ChecklistAnswerEntity> current = currentAnswers(checklist.getId());
        List<ChecklistConflict.MeasuredLine> contradicted = measured.stream()
                .filter(line -> reconciliation(current.get(line.item().getId()), line.measurement())
                        == Reconciliation.CONTRADICTED)
                .map(line -> measuredLine(line.item(), Optional.ofNullable(current.get(line.item().getId())),
                        line.measurement(), null))
                .toList();
        if (!contradicted.isEmpty()) {
            throw ChecklistConflict.measured(Cause.MEASUREMENT_CONTRADICTED, "Revision " + revision + " cannot be "
                    + "submitted: " + contradicted.stream().map(line -> "line " + line.position())
                            .collect(Collectors.joining(", "))
                    + (contradicted.size() == 1 ? " is" : " are") + " answered yes where the measurement fails. Answer "
                    + "no with the reason, or settle the findings by triage.", contradicted);
        }

        transactions.executeWithoutResult(status -> {
            requireStill(checklists.submit(checklist.getId(), seenEdition, ChecklistStatus.DRAFT.wireName(),
                    ChecklistStatus.SUBMITTED.wireName(), now, who.username(), who.accountId()), checklist);
            store(checklist, measured, MeasurementPurpose.SUBMISSION, now, who, current);
        });

        audit.record(who.actor().entry(AuditOperation.CHECKLIST_SUBMITTED, resource(project, revision),
                "Checklist of project \"" + project.name() + "\", revision " + revision + " submitted for sign-off at "
                        + "edition " + seenEdition + tally(measured) + "."));
        return view(project, reread(checklist));
    }

    /**
     * Returns a submitted revision to its authors, with the reason — a draft again, to be answered.
     *
     * @throws InvalidInputException no reason, or one past {@value #MAX_REASON} characters (400)
     * @throws ChecklistConflict {@code checklist-not-submitted}, {@code checklist-changed}
     */
    public ChecklistView returnToAuthors(long projectId, int revision, VisibilityService.Allowance allowance,
            String reason, Integer seenEdition, Participant who) {
        VisibleProject project = requireProject(projectId, allowance);
        ChecklistEntity checklist = requireRevision(project, revision);
        requireEdition(seenEdition);
        String why = BoundedText.optional(reason, MAX_REASON, "The reason");
        if (why == null) {
            throw new InvalidInputException("Say why the checklist is returned: its authors read the reason.");
        }
        requireStatus(checklist, ChecklistStatus.SUBMITTED, Cause.NOT_SUBMITTED, "returned");
        requireSeen(checklist, seenEdition, "returning it");
        Instant now = clock.instant();

        transactions.executeWithoutResult(status -> requireStill(checklists.returnToDraft(checklist.getId(), seenEdition,
                ChecklistStatus.SUBMITTED.wireName(), ChecklistStatus.DRAFT.wireName(), now, who.username(), why),
                checklist));

        audit.record(who.actor().entry(AuditOperation.CHECKLIST_RETURNED, resource(project, revision),
                "Checklist of project \"" + project.name() + "\", revision " + revision + " returned to its authors: "
                        + BoundedText.clip(why, 300)));
        return view(project, reread(checklist));
    }

    /**
     * Signs a submitted revision off: the release attestation.
     *
     * <p><b>Freshness is judged again, here</b> (§6): the measured lines are measured again inside the
     * sign-off, and a line whose outcome or reason is not what the submission stored refuses the
     * sign-off, naming the lines — a signature must not attest to evidence that stopped being true
     * between submission and signature, and a line that started passing since is a picture the
     * submitter did not attest to either. Accepted, the sign-off's measurements are stored with it and
     * the revision's measurements are frozen: a signed-off revision is read back as signed.
     *
     * @throws AccessDeniedException a role that may not approve — refused before anything is read (403)
     * @throws ChecklistConflict {@code checklist-not-submitted}, {@code checklist-changed}, {@code
     *     checklist-four-eyes} when four-eyes is on and the signer wrote the revision, {@code
     *     checklist-incomplete} when a proof stopped holding since the submission, {@code
     *     checklist-measurement-changed} when a measurement did
     */
    public ChecklistView signOff(long projectId, int revision, VisibilityService.Allowance allowance, Integer seenEdition,
            Participant who) {
        // An approver's decision, like a triage: the governor's marker passes the route, and its role
        // decides the rules and takes no decision under them. Refused before the project is read, so the
        // answer depends on nothing but the role.
        Optional<Role> role = who.role();
        if (!role.map(Role::canApproveTriage).orElse(false)) {
            throw new AccessDeniedException(role.map(Role::governsPlatform).orElse(false)
                    ? "Signing a checklist off is an approval, and the platform governor takes none: it decides the "
                            + "rules the others act under."
                    : "Signing a checklist off is an approval, which this role may not give.");
        }
        Guarded guarded = requireWhole(projectId, allowance);
        VisibleProject project = guarded.project();
        ChecklistEntity checklist = requireRevision(project, revision);
        requireEdition(seenEdition);
        requireStatus(checklist, ChecklistStatus.SUBMITTED, Cause.NOT_SUBMITTED, "signed off");
        requireSeen(checklist, seenEdition, "signing it off");

        boolean fourEyes = settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED);
        List<Author> authors = authorsOf(checklist);
        if (fourEyes && wrote(who, authors)) {
            ChecklistConflict refused = new ChecklistConflict(Cause.FOUR_EYES, "Four-eyes approval: revision "
                    + revision + " was written by " + names(authors) + ", so it is signed off by somebody else.");
            audit.record(who.actor().entry(AuditOperation.CHECKLIST_SIGN_OFF_REFUSED, resource(project, revision),
                    "Checklist of project \"" + project.name() + "\", revision " + revision + ": sign-off refused, "
                            + "four-eyes is on and the signer is one of its authors (" + names(authors) + ")."));
            throw refused;
        }
        Instant now = clock.instant();
        List<ChecklistMeasurer.LineMeasurement> measured = measurer.measure(guarded.repositoryIds(),
                items.findByVersionIdOrderByPositionAsc(checklist.getTemplateVersionId()), now);
        List<ChecklistConflict.IncompleteLine> lapsed = incompleteLines(checklist, outcomes(measured));
        if (!lapsed.isEmpty()) {
            audit.record(who.actor().entry(AuditOperation.CHECKLIST_SIGN_OFF_REFUSED, resource(project, revision),
                    "Checklist of project \"" + project.name() + "\", revision " + revision + ": sign-off refused, "
                            + "no longer complete since its submission — " + inWords(lapsed)));
            throw ChecklistConflict.incomplete("Revision " + revision + " cannot be signed off: " + inWords(lapsed)
                    + ". Return it to its authors.", lapsed);
        }
        Map<Long, ChecklistAnswerEntity> current = currentAnswers(checklist.getId());
        Map<Long, ChecklistMeasurementEntity> submitted = newestPerLine(checklist.getId(), MeasurementPurpose.SUBMISSION);
        List<ChecklistConflict.MeasuredLine> changed = new ArrayList<>();
        for (ChecklistMeasurer.LineMeasurement line : measured) {
            ChecklistMeasurementEntity before = submitted.get(line.item().getId());
            Measurement found = line.measurement();
            // Outcome and reason, not the evidence's digest: a scan run since that finds the same is the
            // same picture. The rule's digest too, although a published version's binding cannot move —
            // a measurement of another rule is another claim, whatever it found.
            boolean same = before != null
                    && before.getOutcome().equals(found.outcome().wireName())
                    && java.util.Objects.equals(before.getReason(), found.reason().map(NoDataReason::wireName).orElse(null))
                    && before.getRuleDigest().equals(line.rule().digest());
            if (!same) {
                changed.add(measuredLine(line.item(), Optional.ofNullable(current.get(line.item().getId())), found, before));
            }
        }
        if (!changed.isEmpty()) {
            String lines = changed.stream()
                    .map(line -> "line " + line.position() + " " + (line.submittedOutcome() == null
                            ? "measured nothing at the submission"
                            : "was " + line.submittedOutcome() + (line.submittedReason() == null ? "" : " (" + line.submittedReason() + ")"))
                            + ", now " + line.outcome() + (line.reason() == null ? "" : " (" + line.reason() + ")"))
                    .collect(Collectors.joining("; "));
            audit.record(who.actor().entry(AuditOperation.CHECKLIST_SIGN_OFF_REFUSED, resource(project, revision),
                    "Checklist of project \"" + project.name() + "\", revision " + revision + ": sign-off refused, "
                            + "a measurement changed since the submission — " + lines));
            throw ChecklistConflict.measured(Cause.MEASUREMENT_CHANGED, "Revision " + revision + " cannot be signed off: "
                    + "a measurement changed since its submission — " + lines + ". Return it to its authors.", changed);
        }

        transactions.executeWithoutResult(status -> {
            requireStill(checklists.signOff(checklist.getId(), seenEdition, ChecklistStatus.SUBMITTED.wireName(),
                    ChecklistStatus.SIGNED_OFF.wireName(), now, who.username(), who.accountId(), fourEyes), checklist);
            store(checklist, measured, MeasurementPurpose.SIGN_OFF, now, who, current);
        });

        audit.record(who.actor().entry(AuditOperation.CHECKLIST_SIGNED_OFF, resource(project, revision),
                "Checklist of project \"" + project.name() + "\", revision " + revision + " signed off, submitted by "
                        + checklist.getSubmittedBy() + "; four-eyes " + (fourEyes
                                ? "required, and the signer is none of its authors (" + names(authors) + ")"
                                : "not required") + tally(measured) + "."));
        return view(project, reread(checklist));
    }

    // ------------------------------------------------------------------ measurements (§6)

    /**
     * The measured lines of a revision, each beside its answer: for a draft or a submitted revision what
     * the rules find now, computed for this read and stored nowhere; for a signed-off one what the
     * sign-off froze; for a superseded one the last stored, or nothing — its rules are not applied again
     * to data that has moved on since it stopped being the project's checklist.
     */
    public ChecklistMeasurementsView measurements(long projectId, int revision, VisibilityService.Allowance allowance,
            Participant reader) {
        Guarded guarded = requireWhole(projectId, allowance);
        ChecklistEntity checklist = requireRevision(guarded.project(), revision);
        ChecklistStatus status = ChecklistStatus.ofStored(checklist.getStatus());
        List<ChecklistItemEntity> bound = items.findByVersionIdOrderByPositionAsc(checklist.getTemplateVersionId())
                .stream().filter(item -> item.getBoundRule() != null).toList();
        Map<Long, ChecklistAnswerEntity> current = currentAnswers(checklist.getId());
        Map<Long, ChecklistMeasurementEntity> atSubmission = status == ChecklistStatus.SUBMITTED
                        || status == ChecklistStatus.SIGNED_OFF
                ? newestPerLine(checklist.getId(), MeasurementPurpose.SUBMISSION)
                : Map.of();
        boolean live = status == ChecklistStatus.DRAFT || status == ChecklistStatus.SUBMITTED;
        Instant now = clock.instant();

        Map<Long, ChecklistMeasurementView> shown = new HashMap<>();
        Map<Long, Optional<MeasurementOutcome>> outcomes = new HashMap<>();
        if (live) {
            for (ChecklistMeasurer.LineMeasurement line : measurer.measure(guarded.repositoryIds(), bound, now)) {
                ChecklistAnswerEntity answer = current.get(line.item().getId());
                shown.put(line.item().getId(), liveView(checklist.getId(), line, now, reader, answer));
                outcomes.put(line.item().getId(), Optional.of(line.measurement().outcome()));
            }
        } else {
            Map<Long, ChecklistMeasurementEntity> stored = new HashMap<>(
                    newestPerLine(checklist.getId(), MeasurementPurpose.SUBMISSION));
            stored.putAll(newestPerLine(checklist.getId(), MeasurementPurpose.SIGN_OFF));
            stored.forEach((itemId, row) -> shown.put(itemId, ChecklistMeasurementView.of(row)));
        }

        Map<Long, List<ChecklistEvidenceEntity>> proofs = new HashMap<>();
        evidence.findByChecklistIdOrderByIdAsc(checklist.getId())
                .forEach(row -> proofs.computeIfAbsent(row.getItemId(), id -> new ArrayList<>()).add(row));
        LocalDate today = today();
        List<ChecklistMeasurementsView.MeasuredLineView> lines = new ArrayList<>();
        for (ChecklistItemEntity item : bound) {
            ChecklistAnswerEntity answer = current.get(item.getId());
            ChecklistMeasurementView measurement = shown.get(item.getId());
            Optional<ChecklistAnswer> value = Optional.ofNullable(answer).map(row -> ChecklistAnswer.parse(row.getValue()));
            Optional<MeasurementOutcome> outcome = Optional.ofNullable(measurement)
                    .flatMap(view -> MeasurementOutcome.ofStored(view.outcome()));
            List<String> problems = new ArrayList<>();
            Reconciliation reconciled = Reconciliation.of(value, outcome);
            if (live && reconciled == Reconciliation.CONTRADICTED) {
                problems.add("measurement_contradicted");
            }
            if (live && reconciled == Reconciliation.DECLARED_NOT_MEASURED && value.orElseThrow() == ChecklistAnswer.YES) {
                // What the missing data asks of a "yes": its comment and a proof in date (question 4).
                problems(item, answer, proofs.getOrDefault(item.getId(), List.of()), today, outcome).stream()
                        .filter(problem -> problem.equals("comment_required") || problem.startsWith("evidence_"))
                        .forEach(problems::add);
            }
            ChecklistMeasurementEntity submittedRow = atSubmission.get(item.getId());
            lines.add(new ChecklistMeasurementsView.MeasuredLineView(item.getId(), item.getPosition(), item.getItemKey(),
                    forms.ruleForm(item.getBoundRule()), answer == null ? null : answer.getValue(),
                    answer == null ? null : answer.getId(), measurement,
                    submittedRow == null ? null : ChecklistMeasurementView.of(submittedRow),
                    measurement == null ? Reconciliation.NOT_MEASURED_HERE.wireName()
                            : Reconciliation.of(value, outcome).wireName(),
                    problems));
        }
        return new ChecklistMeasurementsView(guarded.project().projectId(), checklist.getRevision(), checklist.getStatus(),
                live, live ? now : null, lines);
    }

    private ChecklistMeasurementView liveView(long checklistId, ChecklistMeasurer.LineMeasurement line, Instant now,
            Participant reader, ChecklistAnswerEntity answer) {
        Measurement measurement = line.measurement();
        Optional<ChecklistAnswer> value = Optional.ofNullable(answer).map(row -> ChecklistAnswer.parse(row.getValue()));
        return new ChecklistMeasurementView(null, checklistId, line.item().getId(), MeasurementPurpose.READ.wireName(),
                line.rule().kind().wireName(), line.rule().digest(), line.rule().canonical(),
                measurement.outcome().wireName(), measurement.reason().map(NoDataReason::wireName).orElse(null),
                measurement.asOf().orElse(null), now, reader.username(), answer == null ? null : answer.getId(),
                answer == null ? null : answer.getValue(),
                Reconciliation.of(value, Optional.of(measurement.outcome())).wireName(), measurement.evidenceDigest(),
                ChecklistMeasurementView.evidence(measurement));
    }

    /** Stores what the rules found, each with the answer it was reconciled with — inside the caller's transaction. */
    private void store(ChecklistEntity checklist, List<ChecklistMeasurer.LineMeasurement> measured,
            MeasurementPurpose purpose, Instant now, Participant who, Map<Long, ChecklistAnswerEntity> current) {
        measurements.saveAll(measured.stream().map(line -> {
            ChecklistAnswerEntity answer = current.get(line.item().getId());
            return measurementRow(checklist.getId(), line, purpose, now, who, answer,
                    Optional.ofNullable(answer).map(row -> ChecklistAnswer.parse(row.getValue())));
        }).toList());
    }

    private static ChecklistMeasurementEntity measurementRow(long checklistId, ChecklistMeasurer.LineMeasurement line,
            MeasurementPurpose purpose, Instant now, Participant who, ChecklistAnswerEntity answer,
            Optional<ChecklistAnswer> value) {
        Measurement measurement = line.measurement();
        ChecklistMeasurementEntity row = new ChecklistMeasurementEntity();
        row.setChecklistId(checklistId);
        row.setItemId(line.item().getId());
        row.setPurpose(purpose.wireName());
        row.setRuleKind(line.rule().kind().wireName());
        row.setRuleDigest(line.rule().digest());
        row.setBoundRule(line.rule().canonical());
        row.setOutcome(measurement.outcome().wireName());
        row.setReason(measurement.reason().map(NoDataReason::wireName).orElse(null));
        row.setAsOf(measurement.asOf().orElse(null));
        row.setComputedAt(now);
        row.setComputedBy(who.username());
        row.setAnswerId(answer == null ? null : answer.getId());
        row.setAnswerValue(value.map(ChecklistAnswer::wireName).orElse(null));
        row.setReconciliation(Reconciliation.of(value, Optional.of(measurement.outcome())).wireName());
        row.setEvidenceDigest(measurement.evidenceDigest());
        row.setEvidence(measurement.evidenceJson());
        return row;
    }

    /** The newest measurement of each line stored for one purpose — the latest submission's, the sign-off's. */
    private Map<Long, ChecklistMeasurementEntity> newestPerLine(long checklistId, MeasurementPurpose purpose) {
        Map<Long, ChecklistMeasurementEntity> newest = new HashMap<>();
        measurements.findByChecklistIdAndPurposeOrderByIdAsc(checklistId, purpose.wireName())
                .forEach(row -> newest.put(row.getItemId(), row));
        return newest;
    }

    private static Map<Long, MeasurementOutcome> outcomes(List<ChecklistMeasurer.LineMeasurement> measured) {
        Map<Long, MeasurementOutcome> outcomes = new HashMap<>();
        measured.forEach(line -> outcomes.put(line.item().getId(), line.measurement().outcome()));
        return outcomes;
    }

    private static Reconciliation reconciliation(ChecklistAnswerEntity answer, Measurement measurement) {
        return Reconciliation.of(Optional.ofNullable(answer).map(row -> ChecklistAnswer.parse(row.getValue())),
                Optional.of(measurement.outcome()));
    }

    private static ChecklistConflict.MeasuredLine measuredLine(ChecklistItemEntity item,
            Optional<ChecklistAnswerEntity> answer, Measurement measurement, ChecklistMeasurementEntity submitted) {
        return new ChecklistConflict.MeasuredLine(item.getId(), item.getPosition(),
                answer.map(ChecklistAnswerEntity::getValue).orElse(null), measurement.outcome().wireName(),
                measurement.reason().map(NoDataReason::wireName).orElse(null),
                submitted == null ? null : submitted.getOutcome(), submitted == null ? null : submitted.getReason());
    }

    private static String describe(Measurement measurement) {
        return measurement.outcome().wireName()
                + measurement.reason().map(reason -> " (" + reason.wireName() + ")").orElse("");
    }

    /** "; 3 measured lines: 2 pass, 1 no data" — nothing when no line is measured. */
    private static String tally(List<ChecklistMeasurer.LineMeasurement> measured) {
        if (measured.isEmpty()) {
            return "";
        }
        Map<MeasurementOutcome, Long> counted = new java.util.EnumMap<>(MeasurementOutcome.class);
        measured.forEach(line -> counted.merge(line.measurement().outcome(), 1L, Long::sum));
        return "; " + measured.size() + (measured.size() == 1 ? " measured line: " : " measured lines: ")
                + counted.entrySet().stream()
                        .map(entry -> entry.getValue() + " " + entry.getKey().wireName().replace('_', ' '))
                        .collect(Collectors.joining(", "));
    }

    // ------------------------------------------------------------------ the guard and the rows

    private VisibleProject requireProject(long projectId, VisibilityService.Allowance allowance) {
        return requireWhole(projectId, allowance).project();
    }

    /** A project the guard let through, and the repositories it judged it by. */
    private record Guarded(VisibleProject project, List<Long> repositoryIds) {}

    /**
     * The guard, keeping the repositories it compared with the caller's visibility: a measurement reads
     * exactly those — never a second reading of the project, which a repository filed in between would
     * extend past what the guard saw.
     */
    private Guarded requireWhole(long projectId, VisibilityService.Allowance allowance) {
        Optional<SolutionQueryService.ProjectMembers> members = projects.members(projectId);
        List<Long> repositories = List.copyOf(
                members.map(SolutionQueryService.ProjectMembers::repositoryIds).orElse(List.of()));
        VisibleProject project = RowVisibility.requireWhollyVisibleProject(projectId,
                members.map(SolutionQueryService.ProjectMembers::name), repositories, allowance);
        return new Guarded(project, repositories);
    }

    private ChecklistEntity requireRevision(VisibleProject project, int revision) {
        return checklists.findByProjectIdAndRevision(project.projectId(), revision)
                .orElseThrow(() -> new NotFoundException("Project \"" + project.name() + "\" has no checklist revision "
                        + revision + "."));
    }

    private ChecklistItemEntity requireLine(ChecklistEntity checklist, long itemId) {
        return items.findById(itemId)
                .filter(item -> item.getVersionId().equals(checklist.getTemplateVersionId()))
                .orElseThrow(() -> new NotFoundException("Checklist revision " + checklist.getRevision()
                        + " has no line " + itemId + "."));
    }

    private ChecklistEvidenceEntity requireEvidence(ChecklistEntity checklist, long evidenceId) {
        return evidence.findById(evidenceId)
                .filter(row -> row.getChecklistId().equals(checklist.getId()))
                .orElseThrow(() -> new NotFoundException("Checklist revision " + checklist.getRevision()
                        + " has no proof " + evidenceId + "."));
    }

    private void requireLatest(VisibleProject project, ChecklistEntity checklist) {
        checklists.findFirstByProjectIdOrderByRevisionDesc(project.projectId())
                .filter(latest -> !latest.getId().equals(checklist.getId()))
                .ifPresent(latest -> {
                    throw new ChecklistConflict(Cause.NOT_LATEST, "Revision " + checklist.getRevision()
                            + " has been followed by revision " + latest.getRevision() + ": act on that one.");
                });
    }

    private static void requireEdition(Integer seenEdition) {
        if (seenEdition == null) {
            throw new InvalidInputException("State the edition you read — the checklist's \"edition\": a checklist is "
                    + "changed from what somebody has seen.");
        }
    }

    /**
     * The edition the person read is the revision's now. The conditional statement alone compares with
     * the edition this request read a moment earlier, which orders two requests and lets the second
     * act on work its author never saw.
     */
    private static void requireSeen(ChecklistEntity checklist, int seenEdition, String doing) {
        if (checklist.getEdition() != seenEdition) {
            throw new ChecklistConflict(Cause.CHANGED, "Revision " + checklist.getRevision() + " has changed since "
                    + "edition " + seenEdition + " — it is at edition " + checklist.getEdition() + ". Read it again before "
                    + doing + ".");
        }
    }

    private static void requireStatus(ChecklistEntity checklist, ChecklistStatus wanted, Cause cause, String act) {
        if (ChecklistStatus.ofStored(checklist.getStatus()) != wanted) {
            throw new ChecklistConflict(cause, "Revision " + checklist.getRevision() + " is " + checklist.getStatus()
                    + ": only a " + wanted.wireName().replace('_', ' ') + " revision is " + act + ".");
        }
    }

    /** The conditional statement's answer: nothing matched means another write came first. */
    private static void requireStill(int updated, ChecklistEntity checklist) {
        if (updated != 1) {
            throw new ChecklistConflict(Cause.CHANGED, "Revision " + checklist.getRevision() + " changed while this "
                    + "was being done — by somebody else. Read it again.");
        }
    }

    private void requireComplete(ChecklistEntity checklist, String act, Map<Long, MeasurementOutcome> measured) {
        List<ChecklistConflict.IncompleteLine> incomplete = incompleteLines(checklist, measured);
        if (!incomplete.isEmpty()) {
            throw ChecklistConflict.incomplete("Revision " + checklist.getRevision() + " cannot be " + act + ": "
                    + inWords(incomplete) + ".", incomplete);
        }
    }

    private ChecklistEntity reread(ChecklistEntity checklist) {
        return checklists.findById(checklist.getId())
                .orElseThrow(() -> new IllegalStateException("Checklist " + checklist.getId() + " is gone."));
    }

    /**
     * One write on one line of a draft, if the line is as the person read it: nothing written on it
     * after {@code seenEdition}. The write runs in one transaction behind a conditional statement on
     * the edition this request read; if another write came first — on this line or any other — the
     * request reads again and decides again, a few times, before refusing.
     *
     * @param write handed the edition the write is recorded at
     * @return the revision as it is after the write
     */
    private ChecklistEntity writeLine(ChecklistEntity read, long itemId, int seenEdition, IntConsumer write) {
        ChecklistEntity current = read;
        for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
            requireStatus(current, ChecklistStatus.DRAFT, Cause.NOT_DRAFT, "answered and proven");
            if (seenEdition > current.getEdition()) {
                throw new ChecklistConflict(Cause.CHANGED, "Revision " + current.getRevision() + " has no edition "
                        + seenEdition + " yet — it is at edition " + current.getEdition() + ". Read it again.");
            }
            int lineEdition = lineEdition(current.getId(), itemId);
            if (lineEdition > seenEdition) {
                throw new ChecklistConflict(Cause.LINE_CHANGED, "This line of revision " + current.getRevision()
                        + " has changed since edition " + seenEdition + " — somebody wrote on it at edition " + lineEdition
                        + ". Read it again.");
            }
            int edition = current.getEdition();
            long checklistId = current.getId();
            Boolean done = transactions.execute(status -> {
                if (checklists.touchDraft(checklistId, edition, ChecklistStatus.DRAFT.wireName()) != 1) {
                    return false;
                }
                write.accept(edition + 1);
                return true;
            });
            if (Boolean.TRUE.equals(done)) {
                return reread(current);
            }
            current = reread(current);
        }
        throw new ChecklistConflict(Cause.CHANGED, "Revision " + read.getRevision() + " is being changed by somebody "
                + "else right now. Read it again.");
    }

    /** The edition at which a line last changed: its newest answer, proof or withdrawal; 0 for none. */
    private int lineEdition(long checklistId, long itemId) {
        int newest = 0;
        for (ChecklistAnswerEntity row : answers.findByChecklistIdAndItemIdOrderByIdAsc(checklistId, itemId)) {
            newest = Math.max(newest, row.getEdition());
        }
        for (ChecklistEvidenceEntity row : evidence.findByChecklistIdAndItemIdOrderByIdAsc(checklistId, itemId)) {
            newest = Math.max(newest, row.getEdition());
            if (row.getWithdrawnEdition() != null) {
                newest = Math.max(newest, row.getWithdrawnEdition());
            }
        }
        return newest;
    }

    /** The newest answer of each line of a revision. */
    private Map<Long, ChecklistAnswerEntity> currentAnswers(long checklistId) {
        Map<Long, ChecklistAnswerEntity> current = new HashMap<>();
        answers.findByChecklistIdOrderByIdAsc(checklistId).forEach(row -> current.put(row.getItemId(), row));
        return current;
    }

    private Optional<ChecklistAnswerEntity> currentAnswer(long checklistId, long itemId) {
        List<ChecklistAnswerEntity> rows = answers.findByChecklistIdAndItemIdOrderByIdAsc(checklistId, itemId);
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.getLast());
    }

    private static ChecklistAnswerEntity answerRow(long checklistId, long itemId, String value, String comment,
            Participant who, Instant now, Long confirmedFrom, int edition) {
        ChecklistAnswerEntity row = new ChecklistAnswerEntity();
        row.setChecklistId(checklistId);
        row.setItemId(itemId);
        row.setValue(value);
        row.setComment(comment);
        row.setAnsweredBy(who.username());
        row.setAnsweredById(who.accountId());
        row.setAnsweredAt(now);
        row.setCarriedFromId(confirmedFrom);
        row.setNeedsConfirmation(false);
        row.setEdition(edition);
        return row;
    }

    private static ChecklistEvidenceEntity proofRow(ChecklistEntity checklist, ChecklistItemEntity item, LocalDate performed,
            Participant who, Instant now, int edition) {
        ChecklistEvidenceEntity row = new ChecklistEvidenceEntity();
        row.setChecklistId(checklist.getId());
        row.setItemId(item.getId());
        row.setPerformedOn(startOf(performed));
        row.setValidUntil(validUntil(performed, item.getEvidenceValidityMonths()));
        row.setAddedBy(who.username());
        row.setAddedById(who.accountId());
        row.setAddedAt(now);
        row.setEdition(edition);
        return row;
    }

    // ------------------------------------------------------------------ carrying answers (§4)

    /** What a new revision receives from the one it follows. */
    private record Carried(
            List<ChecklistAnswerEntity> answers,
            List<ChecklistEvidenceEntity> evidence,
            int current,
            int toConfirm,
            boolean otherTemplate) {

        static final Carried NOTHING = new Carried(List.of(), List.of(), 0, 0, false);

        String describe() {
            if (otherTemplate) {
                return ", another template: no answer carried.";
            }
            return ": " + current + (current == 1 ? " answer" : " answers") + " carried as current, " + toConfirm
                    + " to be confirmed, " + evidence.size() + (evidence.size() == 1 ? " proof" : " proofs") + " carried.";
        }
    }

    /**
     * The answers and proofs of {@code previous} that follow into a revision on {@code version}, as rows
     * still to be written: the checklist they belong to, the carrier and the instant are set when the
     * revision is opened. Paired by key and content digest — the new version's items already carry the
     * old key where the importer paired them by hand.
     */
    private Carried carryOnto(ChecklistEntity previous, ChecklistTemplateVersionEntity version,
            ChecklistTemplateEntity template) {
        ChecklistTemplateVersionEntity from = versions.findById(previous.getTemplateVersionId())
                .orElseThrow(() -> new IllegalStateException("The version of checklist " + previous.getId() + " is gone."));
        if (!from.getTemplateId().equals(template.getId())) {
            return new Carried(List.of(), List.of(), 0, 0, true);
        }
        List<ChecklistItemEntity> before = items.findByVersionIdOrderByPositionAsc(from.getId());
        List<ChecklistItemEntity> after = items.findByVersionIdOrderByPositionAsc(version.getId());
        Map<String, ChecklistItemEntity> beforeByKey = new HashMap<>();
        before.forEach(item -> beforeByKey.put(item.getItemKey(), item));
        Map<String, ChecklistItemEntity> afterByKey = new HashMap<>();
        after.forEach(item -> afterByKey.put(item.getItemKey(), item));
        boolean offersNotApplicable = forms.layout(version.getLayout()).offersNotApplicable();

        Map<Long, ChecklistAnswerEntity> currentByItem = new HashMap<>();
        answers.findByChecklistIdOrderByIdAsc(previous.getId()).forEach(row -> currentByItem.put(row.getItemId(), row));
        Map<Long, List<ChecklistEvidenceEntity>> proofsByItem = new HashMap<>();
        evidence.findByChecklistIdOrderByIdAsc(previous.getId()).stream()
                .filter(row -> row.getWithdrawnAt() == null)
                .forEach(row -> proofsByItem.computeIfAbsent(row.getItemId(), id -> new ArrayList<>()).add(row));

        List<ChecklistAnswerEntity> carriedAnswers = new ArrayList<>();
        List<ChecklistEvidenceEntity> carriedProofs = new ArrayList<>();
        int current = 0;
        int toConfirm = 0;
        VersionPairing pairing = VersionPairing.of(domains(before), domains(after), List.of());
        for (VersionPairing.Change change : pairing.changes()) {
            ChecklistItem was;
            ChecklistItem next;
            boolean changed;
            switch (change) {
                case VersionPairing.Unchanged unchanged -> {
                    was = unchanged.previous();
                    next = unchanged.next();
                    changed = false;
                }
                case VersionPairing.Changed moved -> {
                    was = moved.previous();
                    next = moved.next();
                    changed = true;
                }
                case VersionPairing.Added ignored -> {
                    continue;
                }
                case VersionPairing.Removed ignored -> {
                    continue;
                }
            }
            ChecklistItemEntity source = beforeByKey.get(was.key().value());
            ChecklistItemEntity target = afterByKey.get(next.key().value());
            ChecklistAnswerEntity answer = currentByItem.get(source.getId());
            if (answer != null) {
                boolean confirm = changed || answer.isNeedsConfirmation()
                        || (ChecklistAnswer.NOT_APPLICABLE.wireName().equals(answer.getValue()) && !offersNotApplicable);
                carriedAnswers.add(carriedAnswer(answer, target.getId(), confirm));
                if (confirm) {
                    toConfirm++;
                } else {
                    current++;
                }
            }
            for (ChecklistEvidenceEntity proof : proofsByItem.getOrDefault(source.getId(), List.of())) {
                carriedProofs.add(carriedProof(proof, target));
            }
        }
        return new Carried(carriedAnswers, carriedProofs, current, toConfirm, false);
    }

    private static List<ChecklistItem> domains(List<ChecklistItemEntity> rows) {
        return rows.stream().map(ChecklistTemplateService::domain).toList();
    }

    private static ChecklistAnswerEntity carriedAnswer(ChecklistAnswerEntity source, long itemId, boolean confirm) {
        ChecklistAnswerEntity row = new ChecklistAnswerEntity();
        row.setItemId(itemId);
        row.setValue(source.getValue());
        row.setComment(source.getComment());
        // The answer is the person's who gave it, then: the copy keeps their name and instant.
        row.setAnsweredBy(source.getAnsweredBy());
        row.setAnsweredById(source.getAnsweredById());
        row.setAnsweredAt(source.getAnsweredAt());
        row.setCarriedFromId(source.getId());
        row.setNeedsConfirmation(confirm);
        return row;
    }

    private static ChecklistEvidenceEntity carriedProof(ChecklistEvidenceEntity source, ChecklistItemEntity target) {
        ChecklistEvidenceEntity row = new ChecklistEvidenceEntity();
        row.setItemId(target.getId());
        row.setKind(source.getKind());
        row.setLink(source.getLink());
        row.setFileId(source.getFileId());
        row.setFileName(source.getFileName());
        row.setMediaType(source.getMediaType());
        row.setFileSize(source.getFileSize());
        row.setFileSha256(source.getFileSha256());
        row.setPerformedOn(source.getPerformedOn());
        // Re-dated against the line it now proves: a version asking for a proof renewed yearly judges an
        // old one by that, whatever the previous line asked.
        row.setValidUntil(validUntil(dayOf(source.getPerformedOn()), target.getEvidenceValidityMonths()));
        row.setAddedBy(source.getAddedBy());
        row.setAddedById(source.getAddedById());
        row.setAddedAt(source.getAddedAt());
        row.setCarriedFromId(source.getId());
        return row;
    }

    /**
     * Opens a revision in one transaction: the previous one superseded if it was open, the new row, and
     * what it carries. Two people opening at once meet at the keys — the project's revision number and
     * its open slot — and the one whose insert fails is answered as stale once the committed rows show
     * the other's revision.
     */
    private ChecklistEntity openRevision(VisibleProject project, ChecklistTemplateVersionEntity version,
            Optional<ChecklistEntity> previous, Carried carried, Participant who) {
        Instant now = clock.instant();
        int next = previous.map(row -> row.getRevision() + 1).orElse(1);
        try {
            return transactions.execute(status -> {
                previous.filter(row -> ChecklistStatus.ofStored(row.getStatus()).isOpen()).ifPresent(row ->
                        requireStill(checklists.supersede(row.getId(), row.getEdition(), ChecklistStatus.OPEN,
                                ChecklistStatus.SUPERSEDED.wireName(), now, who.username()), row));
                ChecklistEntity opened = new ChecklistEntity();
                opened.setProjectId(project.projectId());
                opened.setTemplateVersionId(version.getId());
                opened.setRevision(next);
                opened.setStatus(ChecklistStatus.DRAFT.wireName());
                opened.setEdition(1);
                opened.setOpenSlot(1);
                opened.setAuthorId(who.accountId());
                opened.setAuthor(who.username());
                opened.setOpenedAt(now);
                opened.setOpenedBy(who.username());
                opened.setSupersedesId(previous.map(ChecklistEntity::getId).orElse(null));
                ChecklistEntity saved = checklists.saveAndFlush(opened);
                for (ChecklistAnswerEntity row : carried.answers()) {
                    row.setChecklistId(saved.getId());
                    row.setCarriedBy(who.username());
                    row.setCarriedById(who.accountId());
                    row.setCarriedAt(now);
                    row.setEdition(1);
                }
                answers.saveAll(carried.answers());
                for (ChecklistEvidenceEntity row : carried.evidence()) {
                    row.setChecklistId(saved.getId());
                    row.setCarriedById(who.accountId());
                    row.setEdition(1);
                }
                evidence.saveAll(carried.evidence());
                return saved;
            });
        } catch (ChecklistConflict | InvalidInputException | NotFoundException refusal) {
            throw refusal;
        } catch (RuntimeException failed) {
            // Whatever failed, the transaction rolled back; only the committed rows say whether it was
            // somebody else's revision taking the number or the slot — a lock timeout or a dropped
            // connection is not, and on SQLite a key's refusal is not even a DataIntegrityViolation.
            Optional<ChecklistEntity> now2 = checklists.findFirstByProjectIdOrderByRevisionDesc(project.projectId());
            if (now2.map(ChecklistEntity::getRevision).orElse(0) >= next) {
                throw new ChecklistConflict(Cause.CHANGED, "Somebody else opened revision " + now2.get().getRevision()
                        + " of this project's checklist meanwhile. Read it again.");
            }
            throw failed;
        }
    }

    // ------------------------------------------------------------------ completeness and authors

    /**
     * The lines kept from a submission, each with what keeps it; empty when the revision is ready. A
     * proof is asked of a "yes" only: a "no" or "not applicable" states that the control is not in
     * place, and its comment says why — requiring a document proving a control that is absent would
     * push the honest answer towards the dishonest one.
     */
    private List<ChecklistConflict.IncompleteLine> incompleteLines(ChecklistEntity checklist,
            Map<Long, MeasurementOutcome> measured) {
        return lines(checklist, today(), measured).stream()
                .filter(line -> !line.problems().isEmpty())
                .map(line -> new ChecklistConflict.IncompleteLine(line.itemId(), line.position(), line.problems()))
                .toList();
    }

    /** The lines in the refusal's sentence and the audit entry: "line 2 unanswered; line 3 evidence required". */
    private static String inWords(List<ChecklistConflict.IncompleteLine> lines) {
        return lines.stream()
                .map(line -> "line " + line.position() + " " + String.join(", ", line.problems()).replace('_', ' '))
                .collect(Collectors.joining("; "));
    }

    private List<String> problems(ChecklistItemEntity item, ChecklistAnswerEntity answer,
            List<ChecklistEvidenceEntity> proofs, LocalDate today) {
        return problems(item, answer, proofs, today, Optional.empty());
    }

    /**
     * What keeps a line from a submission, its measurement included when it was taken.
     *
     * <p><b>A "yes" where there is no data is declared, not measured</b> (question 4): allowed, with a
     * comment saying why and a proof — a link or a file, in date — whatever the line itself asks for. The
     * measurement could not see the control; the person says it is in place, and shows it.
     */
    private List<String> problems(ChecklistItemEntity item, ChecklistAnswerEntity answer,
            List<ChecklistEvidenceEntity> proofs, LocalDate today, Optional<MeasurementOutcome> measured) {
        if (answer == null) {
            return List.of("unanswered");
        }
        List<String> problems = new ArrayList<>();
        if (answer.isNeedsConfirmation()) {
            problems.add("awaiting_confirmation");
        }
        ChecklistAnswer value = ChecklistAnswer.parse(answer.getValue());
        boolean declaredNotMeasured = value == ChecklistAnswer.YES
                && measured.filter(MeasurementOutcome.NO_DATA::equals).isPresent();
        if ((value.requiresComment() || declaredNotMeasured)
                && (answer.getComment() == null || answer.getComment().isBlank())) {
            problems.add("comment_required");
        }
        EvidenceRequirement.Kind asked = declaredNotMeasured && evidenceKind(item) == EvidenceRequirement.Kind.NONE
                ? EvidenceRequirement.Kind.LINK_OR_FILE
                : evidenceKind(item);
        if (value == ChecklistAnswer.YES && asked != EvidenceRequirement.Kind.NONE) {
            List<ChecklistEvidenceEntity> eligible = proofs.stream()
                    .filter(proof -> proof.getWithdrawnAt() == null)
                    .filter(proof -> asked == EvidenceRequirement.Kind.LINK_OR_FILE || "file".equals(proof.getKind()))
                    .toList();
            if (eligible.isEmpty()) {
                problems.add("evidence_required");
            } else if (eligible.stream().noneMatch(proof -> inDate(proof, today))) {
                problems.add("evidence_expired");
            }
        }
        return problems;
    }

    /**
     * Everybody who wrote what the revision says: opened a fresh checklist, gave an answer it holds —
     * a carried answer stays its author's — confirmed a carried line, attached or withdrew a proof,
     * submitted it.
     *
     * <p><b>Carrying is not writing.</b> Reopening a signed-off revision, or moving to a new version,
     * copies answers mechanically, and the person who does it has said nothing about any line. Counted
     * as an author, an approver who reopened a checklist could never sign it off; with two approvers,
     * one reopening and the other confirming a line, nobody could (decided on 2026-09-29). So the
     * carrier, and the opener of a revision that supersedes another, are left out; whoever confirms a
     * carried line is not, since confirming is where somebody vouches for it again.
     */
    private List<Author> authorsOf(ChecklistEntity checklist) {
        Set<Author> authors = new LinkedHashSet<>();
        if (checklist.getSupersedesId() == null) {
            authors.add(new Author(checklist.getAuthorId(), checklist.getAuthor()));
        }
        for (ChecklistAnswerEntity row : answers.findByChecklistIdOrderByIdAsc(checklist.getId())) {
            authors.add(new Author(row.getAnsweredById(), row.getAnsweredBy()));
        }
        for (ChecklistEvidenceEntity row : evidence.findByChecklistIdOrderByIdAsc(checklist.getId())) {
            authors.add(new Author(row.getAddedById(), row.getAddedBy()));
            if (row.getWithdrawnById() != null) {
                authors.add(new Author(row.getWithdrawnById(), row.getWithdrawnBy()));
            }
        }
        if (checklist.getSubmittedById() != null) {
            authors.add(new Author(checklist.getSubmittedById(), checklist.getSubmittedBy()));
        }
        // A carried proof names its carrier by account alone; they carried answers too, which named them.
        return List.copyOf(authors);
    }

    /** Compared as two people, like the triage: the account, and its name — a name reused is refused too. */
    private static boolean wrote(Participant who, List<Author> authors) {
        String name = who.username() == null ? "" : who.username().strip();
        return authors.stream().anyMatch(author -> author.accountId() == who.accountId()
                || (author.username() != null && author.username().strip().equalsIgnoreCase(name)));
    }

    private static String names(List<Author> authors) {
        return authors.stream().map(Author::username).distinct().collect(Collectors.joining(", "));
    }

    // ------------------------------------------------------------------ views

    /** A template version as a summary names it. */
    private record VersionRef(String templateSlug, String templateName, int ordinal, String label) {}

    private VersionRef versionRef(long versionId) {
        ChecklistTemplateVersionEntity version = versions.findById(versionId)
                .orElseThrow(() -> new IllegalStateException("Template version " + versionId + " is gone."));
        ChecklistTemplateEntity template = templateOf(version);
        return new VersionRef(template.getSlug(), template.getName(), version.getOrdinal(), version.getLabel());
    }

    private ChecklistTemplateEntity templateOf(ChecklistTemplateVersionEntity version) {
        return templates.findById(version.getTemplateId())
                .orElseThrow(() -> new IllegalStateException("Template " + version.getTemplateId() + " is gone."));
    }

    private ChecklistRevisionSummary summary(ChecklistEntity row, VersionRef version, Map<Long, Integer> revisionOf) {
        Integer supersedes = row.getSupersedesId() == null ? null : revisionOf.computeIfAbsent(row.getSupersedesId(),
                id -> checklists.findById(id).map(ChecklistEntity::getRevision).orElse(null));
        return new ChecklistRevisionSummary(row.getProjectId(), row.getRevision(), row.getStatus(), row.getEdition(),
                version.templateSlug(), version.templateName(), version.ordinal(), version.label(), row.getAuthor(),
                row.getOpenedAt(), row.getOpenedBy(), supersedes, row.getSubmittedAt(), row.getSubmittedBy(),
                row.getReturnedAt(), row.getReturnedBy(), row.getReturnReason(), row.getSignedOffAt(), row.getSignedOffBy(),
                row.getSignOffFourEyes(), row.getSupersededAt(), row.getSupersededBy());
    }

    private ChecklistView view(VisibleProject project, ChecklistEntity checklist) {
        ChecklistTemplateVersionEntity version = versions.findById(checklist.getTemplateVersionId())
                .orElseThrow(() -> new IllegalStateException("The version of checklist " + checklist.getId() + " is gone."));
        AnswerWords words = forms.layout(version.getLayout()).answers();
        List<ChecklistLineView> lines = lines(checklist, today());
        boolean ready = ChecklistStatus.ofStored(checklist.getStatus()) == ChecklistStatus.DRAFT
                && lines.stream().allMatch(line -> line.problems().isEmpty());
        return new ChecklistView(summary(checklist, versionRef(version.getId()), new HashMap<>()), project.name(),
                words.offersNotApplicable(),
                new ChecklistView.AnswerWordsView(words.yes(), words.no(), words.notApplicable().orElse(null)),
                authorsOf(checklist).stream().map(Author::username).distinct().toList(),
                settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED), ready, lines);
    }

    private List<ChecklistLineView> lines(ChecklistEntity checklist, LocalDate today) {
        return lines(checklist, today, Map.of());
    }

    /**
     * @param measured the outcome of each measured line, when a submission or a sign-off has just taken
     *     it; a read takes none, and its lines' problems are those of the answers and proofs alone — the
     *     measurements route names what a measurement adds
     */
    private List<ChecklistLineView> lines(ChecklistEntity checklist, LocalDate today, Map<Long, MeasurementOutcome> measured) {
        Map<Long, ChecklistAnswerEntity> current = new LinkedHashMap<>();
        Map<Long, List<ChecklistEvidenceEntity>> proofs = new HashMap<>();
        Map<Long, Integer> editions = new HashMap<>();
        for (ChecklistAnswerEntity row : answers.findByChecklistIdOrderByIdAsc(checklist.getId())) {
            current.put(row.getItemId(), row);
            editions.merge(row.getItemId(), row.getEdition(), Math::max);
        }
        for (ChecklistEvidenceEntity row : evidence.findByChecklistIdOrderByIdAsc(checklist.getId())) {
            proofs.computeIfAbsent(row.getItemId(), id -> new ArrayList<>()).add(row);
            editions.merge(row.getItemId(), row.getEdition(), Math::max);
            if (row.getWithdrawnEdition() != null) {
                editions.merge(row.getItemId(), row.getWithdrawnEdition(), Math::max);
            }
        }
        return items.findByVersionIdOrderByPositionAsc(checklist.getTemplateVersionId()).stream()
                .sorted(Comparator.comparing(ChecklistItemEntity::getPosition))
                .map(item -> {
                    ChecklistAnswerEntity answer = current.get(item.getId());
                    List<ChecklistEvidenceEntity> attached = proofs.getOrDefault(item.getId(), List.of());
                    return new ChecklistLineView(item.getId(), item.getItemKey(), item.getPosition(), item.getDomain(),
                            item.getObjective(), item.getControl(), item.getContact(), item.getKpi(),
                            item.getEvidenceKind(), item.getEvidenceValidityMonths(),
                            item.getBoundRule() == null ? null : forms.ruleForm(item.getBoundRule()),
                            answer == null ? null : ChecklistAnswerView.of(answer),
                            attached.stream().map(row -> evidenceView(row, today)).toList(),
                            editions.getOrDefault(item.getId(), 0),
                            problems(item, answer, attached, today, Optional.ofNullable(measured.get(item.getId()))));
                })
                .toList();
    }

    private static ChecklistEvidenceView evidenceView(ChecklistEvidenceEntity row, LocalDate today) {
        return new ChecklistEvidenceView(row.getId(), row.getItemId(), row.getKind(), row.getLink(), row.getFileName(),
                row.getMediaType(), row.getFileSize(), row.getFileSha256(), dayOf(row.getPerformedOn()),
                row.getValidUntil() == null ? null : dayOf(row.getValidUntil()), row.getAddedBy(), row.getAddedAt(),
                row.getCarriedFromId(), row.getEdition(), row.getWithdrawnBy(), row.getWithdrawnAt(), inDate(row, today));
    }

    // ------------------------------------------------------------------ values

    private AnswerWords wordsOf(ChecklistEntity checklist) {
        ChecklistTemplateVersionEntity version = versions.findById(checklist.getTemplateVersionId())
                .orElseThrow(() -> new IllegalStateException("The version of checklist " + checklist.getId() + " is gone."));
        return forms.layout(version.getLayout()).answers();
    }

    private static EvidenceRequirement.Kind evidenceKind(ChecklistItemEntity item) {
        return EvidenceRequirement.Kind.valueOf(item.getEvidenceKind().toUpperCase(Locale.ROOT));
    }

    private static boolean inDate(ChecklistEvidenceEntity proof, LocalDate today) {
        return proof.getWithdrawnAt() == null
                && (proof.getValidUntil() == null || !dayOf(proof.getValidUntil()).isBefore(today));
    }

    private LocalDate today() {
        return LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
    }

    private static Instant startOf(LocalDate day) {
        return day.atStartOfDay(ZoneOffset.UTC).toInstant();
    }

    private static LocalDate dayOf(Instant instant) {
        return LocalDate.ofInstant(instant, ZoneOffset.UTC);
    }

    /** The last day a proof holds: performed on, plus the line's validity. None when the line states none. */
    private static Instant validUntil(LocalDate performed, Integer validityMonths) {
        return validityMonths == null ? null : startOf(performed.plusMonths(validityMonths));
    }

    /** A day as a person states it — {@code 2026-09-28} — neither before 1970 nor after today. */
    private LocalDate requireDay(String value) {
        if (value == null || value.isBlank()) {
            throw new InvalidInputException("State the day the work was done — \"performedOn\", as 2026-09-28.");
        }
        LocalDate day;
        try {
            day = LocalDate.parse(value.strip());
        } catch (DateTimeParseException unreadable) {
            throw new InvalidInputException("\"" + BoundedText.clip(value.strip(), 20) + "\" is not a day: write it as "
                    + "2026-09-28.");
        }
        if (day.isAfter(today())) {
            throw new InvalidInputException("A proof is of work already done: " + day + " is in the future.");
        }
        if (day.isBefore(EARLIEST_PROOF)) {
            throw new InvalidInputException("A proof dated " + day + " is before " + EARLIEST_PROOF + ".");
        }
        return day;
    }

    /** An {@code https:} or {@code http:} address with a host, as written, bounded. */
    private static String requireLink(String value) {
        String link = value == null ? "" : value.strip();
        if (link.isEmpty()) {
            throw new InvalidInputException("A link proof names its address, \"link\".");
        }
        if (link.length() > MAX_LINK) {
            throw new InvalidInputException("A link is at most " + MAX_LINK + " characters; this one has "
                    + link.length() + ".");
        }
        try {
            URI uri = new URI(link);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if ((scheme.equals("https") || scheme.equals("http")) && uri.getHost() != null && !uri.getHost().isBlank()) {
                return link;
            }
        } catch (URISyntaxException unreadable) {
            // Refused below, in the same words as a link of another scheme.
        }
        throw new InvalidInputException("A link proof is an https: or http: address with a host; \""
                + BoundedText.clip(link, 60) + "\" is not one.");
    }

    /**
     * A file's name as the download will offer it: its last path segment, without control characters,
     * at most {@value #MAX_FILE_NAME} characters. It names the attachment and is never a path.
     */
    private static String requireFileName(String value) {
        String name = value == null ? "" : value.strip();
        int slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        name = name.substring(slash + 1).replaceAll("\\p{Cntrl}", "").strip();
        if (name.isEmpty() || name.equals(".") || name.equals("..")) {
            throw new InvalidInputException("Name the file — \"name\", as it should be downloaded.");
        }
        if (name.length() > MAX_FILE_NAME) {
            throw new InvalidInputException("A file's name is at most " + MAX_FILE_NAME + " characters; this one has "
                    + name.length() + ".");
        }
        return name;
    }

    private static String resource(VisibleProject project, int revision) {
        return project.projectId() + "/" + revision;
    }
}
