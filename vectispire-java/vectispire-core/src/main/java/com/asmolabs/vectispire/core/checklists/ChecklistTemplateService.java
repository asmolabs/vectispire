package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.checklists.AnswerWords;
import com.asmolabs.vectispire.common.domain.checklists.CellRef;
import com.asmolabs.vectispire.common.domain.checklists.CellValue;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistColumn;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistItem;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistLayout;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistRule;
import com.asmolabs.vectispire.common.domain.checklists.EvidenceRequirement;
import com.asmolabs.vectispire.common.domain.checklists.HeaderCell;
import com.asmolabs.vectispire.common.domain.checklists.ItemKey;
import com.asmolabs.vectispire.common.domain.checklists.LayoutProposal;
import com.asmolabs.vectispire.common.domain.checklists.Sheet;
import com.asmolabs.vectispire.common.domain.checklists.TemplateVersion;
import com.asmolabs.vectispire.common.domain.checklists.VersionPairing;
import com.asmolabs.vectispire.common.domain.checklists.Workbook;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.checklists.ChecklistConflict.Cause;
import com.asmolabs.vectispire.core.checklists.internal.StoredForms;
import com.asmolabs.vectispire.core.checklists.internal.StoredForms.DraftAuthor;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionSummary;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.unit.DataSize;

/**
 * The organisation's checklist templates: a workbook imported as a draft, its layout confirmed by a
 * person, its items paired with the previous version, then published — never in one step (decision
 * 0032 §3, §4).
 *
 * <h2>Who decides what (§8)</h2>
 *
 * <p>Importing, editing a draft, deriving, publishing and retiring are governance work — the routes
 * carry {@code @RequiresSecurityLead}, which admits exactly the roles that {@code canWriteGovernance}.
 * <b>With four-eyes on, a version is published or retired by somebody who did not write it</b>
 * (open question 9): publishing changes what every project attests to. "Wrote" is every account that
 * imported or derived the draft, confirmed its layout or paired its items — the ADR names the importer,
 * and a second person who reshaped the draft is as much its author. Compared as two people, like the
 * triage: the account, and its name — a name reused by another account is refused too. Setting a draft
 * aside is not publishing and asks nobody else: it changes nothing any project attests to.
 *
 * <h2>What a person has seen is what is published</h2>
 *
 * <p>Every change to a version is a conditional update on the revision its writer read, so two edits
 * of one draft cannot interleave and a publication cannot overtake an edit. <b>The writer is the
 * person, not the request</b>: confirming a layout, pairing items and publishing each name the
 * revision the person read on screen, and a draft changed since is refused. The first version of
 * this class compared the edits with the revision the request itself had just read, which ordered
 * two requests but let one lead's layout silently replace another's. Publishing is the case that
 * matters most: an author's edit made after the review refuses the publication rather than being
 * published unseen, which a check of the status alone would let through.
 *
 * <p><b>Every 409 names its cause</b> — a {@link ChecklistConflict}, whose {@code checklist-template-…}
 * token (or {@code checklist-four-eyes}) the problem's {@code type} ends with — so that a screen offers
 * to read the draft again, to derive a new version, or to hand the publication to somebody else,
 * without reading the sentence.
 *
 * <p><b>Every write is audited after its transaction commits</b> — the audit log opens its own, and
 * on SQLite would wait on this one's file lock. Publishing a version, and retiring a published one,
 * signal {@code VECTI-SEC-024} to the SIEM (§9).
 */
@Service
public class ChecklistTemplateService {

    /** The most cells of a sheet a preview carries; a template is a few hundred, a catalogue more. */
    public static final int PREVIEW_CELLS = 20_000;

    /** Column {@code t_checklist_template.slug}, and what a URL segment reads without escaping. */
    static final Pattern SLUG = Pattern.compile("[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?");

    static final int MAX_NAME = 200;
    static final int MAX_LABEL = 200;

    /** Column {@code t_checklist_item.item_key}. */
    private static final int MAX_KEY = 255;

    /** The lines an evidence entry of the audit log names one by one; a whole catalogue would be a page. */
    private static final int AUDITED_LINES = 20;

    private final ChecklistTemplateRepository templates;
    private final ChecklistTemplateVersionRepository versions;
    private final ChecklistItemRepository items;
    private final StoredForms forms;
    private final SettingsService settings;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final long maxWorkbookBytes;

    public ChecklistTemplateService(
            ChecklistTemplateRepository templates,
            ChecklistTemplateVersionRepository versions,
            ChecklistItemRepository items,
            StoredForms forms,
            SettingsService settings,
            AuditLogService audit,
            TransactionTemplate transactions,
            Clock clock,
            @Value("${vectispire.http.max-body.checklist-template-import:10MB}") DataSize maxWorkbook) {
        this.templates = templates;
        this.versions = versions;
        this.items = items;
        this.forms = forms;
        this.settings = settings;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
        this.maxWorkbookBytes = maxWorkbook.toBytes();
    }

    /**
     * Who is writing: the account four-eyes compares, and the actor the audit entry names.
     *
     * @param accountId the signed-in account — never a name taken from the request
     */
    public record Editor(long accountId, RequestActor actor) {

        String username() {
            return actor == null || actor.username() == null ? "unknown" : actor.username();
        }

        boolean wrote(List<DraftAuthor> authors) {
            return authors.stream().anyMatch(author -> author.accountId() == accountId
                    || (author.username() != null && author.username().strip().equalsIgnoreCase(username().strip())));
        }
    }

    // ------------------------------------------------------------------ reads

    public List<ChecklistTemplateView> list() {
        return templates.findAllByOrderBySlugAsc().stream().map(this::view).toList();
    }

    public ChecklistTemplateView template(String slug) {
        return view(requireTemplate(slug));
    }

    public ChecklistVersionView version(String slug, int ordinal) {
        ChecklistTemplateEntity template = requireTemplate(slug);
        return versionView(template, requireVersion(template, ordinal).getId());
    }

    /**
     * What the importer looks at before confirming: the reader's proposal, the confirmed layout, the
     * sheet's cells and the pairing with the previous version.
     *
     * @param sheet the sheet whose cells to show; blank for the confirmed layout's, else the proposal's
     */
    public ChecklistTemplatePreview preview(String slug, int ordinal, String sheet) {
        ChecklistTemplateEntity template = requireTemplate(slug);
        ChecklistTemplateVersionEntity version = requireVersion(template, ordinal);
        Workbook workbook = stored(version);
        LayoutProposal proposal = LayoutProposal.of(workbook);
        Optional<ChecklistLayout> layout = Optional.ofNullable(version.getLayout()).map(forms::layout);

        String shown = sheet != null && !sheet.isBlank()
                ? sheet.strip()
                : layout.map(ChecklistLayout::sheet).orElse(proposal.sheet());
        Sheet cells = workbook.sheet(shown).orElseThrow(() -> new InvalidInputException("The workbook has no sheet \""
                + BoundedText.clip(shown, 40) + "\"; it has " + workbook.sheets().stream().map(Sheet::name)
                        .map(name -> "\"" + name + "\"").collect(Collectors.joining(", ")) + "."));

        List<ChecklistTemplatePreview.PreviewCell> shownCells = new ArrayList<>();
        for (Map.Entry<CellRef, CellValue> cell : cells.cells().entrySet()) {
            if (shownCells.size() == PREVIEW_CELLS) {
                break;
            }
            shownCells.add(new ChecklistTemplatePreview.PreviewCell(cell.getKey().toString(), cell.getKey().row(),
                    cell.getKey().columnLetters(), cell.getValue().text(), cell.getValue() instanceof CellValue.Formula));
        }

        Map<ItemKey, ItemKey> readKeyOf = readKeys(version);
        List<ChecklistTemplatePreview.PairingChange> pairing = layout.isPresent()
                ? pairingOf(version).changes().stream().map(change -> change(change, readKeyOf)).toList()
                : List.of();
        return new ChecklistTemplatePreview(template.getSlug(), summary(template, version.getId()),
                workbook.sheets().stream().map(Sheet::name).toList(), cells.name(), shownCells,
                cells.cells().size() > PREVIEW_CELLS, proposed(proposal),
                layout.map(ChecklistLayoutForm::of).orElse(null), pairing);
    }

    // ------------------------------------------------------------------ writes

    /**
     * Imports a workbook as the template's next version, a draft. The template is created when the
     * slug is new; {@code name} names it then, and is not used otherwise.
     *
     * @throws InvalidInputException a slug, name or label refused, or a file the reader refuses —
     *     not an {@code .xlsx}, past a zip or XML guard (400)
     * @throws ChecklistConflict {@code checklist-template-has-draft} (409): one at a time, so that what a
     *     draft is paired with, and which number it takes, are never in question
     */
    public ChecklistVersionView importWorkbook(String slug, String name, String label, byte[] file, Editor editor) {
        String templateSlug = requireSlug(slug);
        String templateName = BoundedText.optional(name, MAX_NAME, "The template's name");
        String versionLabel = BoundedText.optional(label, MAX_LABEL, "The version's label");
        if (file == null || file.length == 0) {
            throw new InvalidInputException("The body is the template's .xlsx workbook, and it is empty.");
        }
        // Read before any transaction opens: parsing is the costly part and needs no row.
        Workbook workbook = Workbook.read(file, maxWorkbookBytes);
        Instant now = clock.instant();

        record Imported(ChecklistTemplateEntity template, ChecklistTemplateVersionEntity version, boolean created) {}
        Imported imported = arbitrated(templateSlug, () -> transactions.execute(status -> {
            Optional<ChecklistTemplateEntity> existing = templates.findBySlug(templateSlug);
            ChecklistTemplateEntity template = existing.orElseGet(() -> {
                ChecklistTemplateEntity created = new ChecklistTemplateEntity();
                created.setSlug(templateSlug);
                created.setName(templateName == null ? templateSlug : templateName);
                created.setCreatedAt(now);
                created.setCreatedBy(editor.username());
                return templates.save(created);
            });
            requireNoDraft(template);
            ChecklistTemplateVersionEntity version = newVersion(template, versionLabel, editor, now);
            version.setSourceBytes(file);
            version.setSourceSha256(workbook.sha256());
            version.setSourceSize((long) file.length);
            version.setPreviousVersionId(versions.publishedNewestFirst(template.getId()).stream().findFirst().orElse(null));
            return new Imported(template, versions.save(version), existing.isEmpty());
        }));

        audit.record(editor.actor().entry(AuditOperation.CHECKLIST_TEMPLATE_IMPORTED,
                resource(imported.template(), imported.version().getOrdinal()),
                (imported.created() ? "Checklist template \"" + templateSlug + "\" created; its " : "Checklist template \""
                        + templateSlug + "\": ") + "version " + imported.version().getOrdinal()
                        + " imported as a draft from a workbook of " + file.length + " bytes, sha256 "
                        + workbook.sha256() + "."));
        return versionView(imported.template(), imported.version().getId());
    }

    /**
     * Confirms a draft's layout and answer words, and reads its items from the workbook by them —
     * blank domain and objective cells filled down, rows without a control left out. Pairs made
     * earlier are cleared: they named items as the previous layout read them. Evidence requirements
     * and bound rules are kept, by key ({@link #keepingEvidence}).
     *
     * @param seenRevision the revision the editor read — a draft edited since is refused
     */
    public ChecklistVersionView confirmLayout(
            String slug, int ordinal, Integer seenRevision, ChecklistLayoutForm form, Editor editor) {
        ChecklistLayout layout = parse(form);
        ChecklistTemplateEntity template = requireTemplate(slug);
        ChecklistTemplateVersionEntity version = requireDraft(requireVersion(template, ordinal), "have its layout confirmed");
        requireSeen(template, version, seenRevision, "confirming its layout");
        TemplateVersion read = TemplateVersion.read(stored(version), layout);
        List<ChecklistItem> lines = keepingEvidence(version, read.items());

        List<DraftAuthor> authors = withAuthor(forms.authors(version.getDraftAuthors()), editor);
        transactions.executeWithoutResult(status -> {
            requireStill(versions.editDraft(version.getId(), version.getRevision(), TemplateVersionStatus.DRAFT.wireName(),
                    forms.layout(layout), layout.offersNotApplicable(), null, forms.authors(authors)), version);
            replaceItems(version.getId(), lines);
        });

        audit.record(editor.actor().entry(AuditOperation.CHECKLIST_TEMPLATE_LAYOUT_CONFIRMED,
                resource(template, ordinal),
                "Checklist template \"" + template.getSlug() + "\" version " + ordinal + ": layout confirmed on sheet \""
                        + layout.sheet() + "\", rows " + layout.firstItemRow() + " to " + layout.lastItemRow() + ", "
                        + read.items().size() + " items; answers \"" + layout.answers().yes() + "\" / \""
                        + layout.answers().no() + "\"" + layout.answers().notApplicable()
                                .map(word -> " / \"" + word + "\" (not applicable)").orElse(", no not applicable")
                        + "."));
        return versionView(template, version.getId());
    }

    /**
     * Pairs a draft's items by hand with the previous version's — "same control, reworded": the new
     * item takes the old key, so that a project's answer follows it, to be confirmed (§4). The list
     * replaces the draft's pairs; an empty one clears them.
     *
     * @param seenRevision the revision the editor read — a draft edited since is refused, since the
     *     list sent replaces pairs somebody else may have made meanwhile
     */
    public ChecklistVersionView pairItems(
            String slug, int ordinal, Integer seenRevision, List<ChecklistItemPair> requested, Editor editor) {
        List<VersionPairing.ManualPair> pairs = parsePairs(requested);
        ChecklistTemplateEntity template = requireTemplate(slug);
        ChecklistTemplateVersionEntity version = requireDraft(requireVersion(template, ordinal), "have its items paired");
        requireSeen(template, version, seenRevision, "pairing its items");
        requireLayout(version, "pairing its items");
        if (version.getPreviousVersionId() == null) {
            throw new ChecklistConflict(Cause.TEMPLATE_NOTHING_TO_PAIR, "Version " + ordinal + " of \""
                    + template.getSlug() + "\" follows no published version: there is nothing to pair its items with.");
        }
        VersionPairing pairing = VersionPairing.of(itemsOf(version.getPreviousVersionId()), asRead(version), pairs);

        List<DraftAuthor> authors = withAuthor(forms.authors(version.getDraftAuthors()), editor);
        transactions.executeWithoutResult(status -> {
            requireStill(versions.editDraft(version.getId(), version.getRevision(), TemplateVersionStatus.DRAFT.wireName(),
                    version.getLayout(), version.isOffersNotApplicable(), forms.pairs(pairs), forms.authors(authors)),
                    version);
            replaceItems(version.getId(), pairing.next());
        });

        audit.record(editor.actor().entry(AuditOperation.CHECKLIST_TEMPLATE_ITEMS_PAIRED, resource(template, ordinal),
                "Checklist template \"" + template.getSlug() + "\" version " + ordinal + ": " + pairs.size()
                        + (pairs.size() == 1 ? " item" : " items") + " paired by hand with version "
                        + ordinalOf(version.getPreviousVersionId()) + "; their answers follow them, to be confirmed."));
        return versionView(template, version.getId());
    }

    /**
     * Sets what proof some of a draft's lines ask for, and how long a proof holds (decision 0032 §2):
     * the lines listed change, the others keep theirs. The requirement is part of each line's content
     * digest, so a line whose requirement moved is <em>changed</em> against the previous version, and
     * an answer carried onto it waits for a person's confirmation (§4) — asking for a file where a word
     * sufficed is asking something else.
     *
     * <p><b>Why a route of its own.</b> The ADR defines the requirement and checks it at submission,
     * and said nowhere who sets it; the import read every line as {@code none}, so no proof was ever
     * required. A requirement is the template's, not the workbook's — no column of the organisation's
     * sheet states it — so a person sets it on the draft, like the layout, before somebody else
     * publishes it.
     *
     * @param seenRevision the revision the editor read — a draft edited since is refused
     * @throws InvalidInputException no revision, no line, a line named twice or not in the version, a
     *     requirement that is none, a validity outside 1 to 120 months or given to a line asking for no
     *     proof (400)
     * @throws ChecklistConflict {@code checklist-template-not-draft}, {@code checklist-template-no-layout},
     *     {@code checklist-template-changed} (409)
     */
    public ChecklistVersionView setEvidence(
            String slug, int ordinal, Integer seenRevision, List<ChecklistItemEvidence> requested, Editor editor) {
        Map<String, EvidenceRequirement> wanted = parseEvidence(requested);
        ChecklistTemplateEntity template = requireTemplate(slug);
        ChecklistTemplateVersionEntity version = requireDraft(requireVersion(template, ordinal),
                "have its evidence requirements set");
        requireSeen(template, version, seenRevision, "setting its evidence requirements");
        requireLayout(version, "setting its evidence requirements");

        Map<String, ChecklistItemEntity> byKey = new LinkedHashMap<>();
        items.findByVersionIdOrderByPositionAsc(version.getId()).forEach(item -> byKey.put(item.getItemKey(), item));
        List<ChecklistItemEntity> changed = new ArrayList<>();
        List<String> described = new ArrayList<>();
        wanted.forEach((key, evidence) -> {
            ChecklistItemEntity item = byKey.get(key);
            if (item == null) {
                throw new InvalidInputException("Version " + ordinal + " of \"" + template.getSlug() + "\" has no item \""
                        + BoundedText.clip(key, 60) + "\"; a line is named by its key as the version shows it.");
            }
            ChecklistItem requiring = domain(item).withEvidence(evidence);
            item.setEvidenceKind(evidence.kind().wireName());
            item.setEvidenceValidityMonths(evidence.validityMonths().orElse(null));
            // The digest is what the version's view and its documents state: a requirement written
            // without it would say the line asks what it asked before.
            item.setContentDigest(requiring.contentDigest());
            changed.add(item);
            described.add("line " + item.getPosition() + " (row " + item.getSheetRow() + ") " + describe(evidence));
        });

        List<DraftAuthor> authors = withAuthor(forms.authors(version.getDraftAuthors()), editor);
        transactions.executeWithoutResult(status -> {
            requireStill(versions.editDraft(version.getId(), version.getRevision(), TemplateVersionStatus.DRAFT.wireName(),
                    version.getLayout(), version.isOffersNotApplicable(), version.getItemPairs(), forms.authors(authors)),
                    version);
            items.saveAll(changed);
        });

        audit.record(editor.actor().entry(AuditOperation.CHECKLIST_TEMPLATE_EVIDENCE_SET, resource(template, ordinal),
                "Checklist template \"" + template.getSlug() + "\" version " + ordinal + ": evidence requirement set on "
                        + changed.size() + (changed.size() == 1 ? " line — " : " lines — ")
                        + String.join("; ", described.subList(0, Math.min(described.size(), AUDITED_LINES)))
                        + (described.size() > AUDITED_LINES
                                ? "; and " + (described.size() - AUDITED_LINES) + " more"
                                : "")
                        + "."));
        return versionView(template, version.getId());
    }

    /**
     * Binds a rule to some of a draft's lines, or unbinds them (decision 0032 §6): the lines listed
     * change, the others keep theirs. Each rule is read by the domain, which refuses in words a kind
     * that is none, a parameter another kind takes, a maximum age missing or out of bounds, a scope
     * nothing examines, a threshold that checks nothing — no parameter is assumed.
     *
     * <p>The binding is part of each line's content digest (§2), so a line whose binding moved is
     * <em>changed</em> against the previous version and an answer carried onto it waits for a person's
     * confirmation (§4): a "yes" measured by another rule is another claim.
     *
     * @param seenRevision the revision the editor read — a draft edited since is refused
     * @throws InvalidInputException no revision, no line, a line named twice or not in the version, a
     *     rule the domain refuses (400)
     * @throws ChecklistConflict {@code checklist-template-not-draft}, {@code checklist-template-no-layout},
     *     {@code checklist-template-changed} (409)
     */
    public ChecklistVersionView bindRules(
            String slug, int ordinal, Integer seenRevision, List<ChecklistItemRule> requested, Editor editor) {
        Map<String, Optional<ChecklistRule>> wanted = parseRules(requested);
        ChecklistTemplateEntity template = requireTemplate(slug);
        ChecklistTemplateVersionEntity version = requireDraft(requireVersion(template, ordinal), "have its rules bound");
        requireSeen(template, version, seenRevision, "binding its rules");
        requireLayout(version, "binding its rules");

        Map<String, ChecklistItemEntity> byKey = new LinkedHashMap<>();
        items.findByVersionIdOrderByPositionAsc(version.getId()).forEach(item -> byKey.put(item.getItemKey(), item));
        List<ChecklistItemEntity> changed = new ArrayList<>();
        List<String> described = new ArrayList<>();
        wanted.forEach((key, rule) -> {
            ChecklistItemEntity item = byKey.get(key);
            if (item == null) {
                throw new InvalidInputException("Version " + ordinal + " of \"" + template.getSlug() + "\" has no item \""
                        + BoundedText.clip(key, 60) + "\"; a line is named by its key as the version shows it.");
            }
            Optional<String> canonical = rule.map(ChecklistRule::canonical);
            item.setBoundRule(canonical.orElse(null));
            // The digest is what the version's view and every pairing read: a binding written without it
            // would say the line asks what it asked before, and a carried answer would not wait.
            item.setContentDigest(domain(item).withBoundRule(canonical).contentDigest());
            changed.add(item);
            described.add("line " + item.getPosition() + " (row " + item.getSheetRow() + ") "
                    + rule.map(bound -> "bound to " + bound.kind().wireName() + ", evidence at most "
                            + bound.maxAgeDays() + (bound.maxAgeDays() == 1 ? " day" : " days") + " old, rule sha256 "
                            + bound.digest().substring(0, 12)).orElse("unbound"));
        });

        List<DraftAuthor> authors = withAuthor(forms.authors(version.getDraftAuthors()), editor);
        transactions.executeWithoutResult(status -> {
            requireStill(versions.editDraft(version.getId(), version.getRevision(), TemplateVersionStatus.DRAFT.wireName(),
                    version.getLayout(), version.isOffersNotApplicable(), version.getItemPairs(), forms.authors(authors)),
                    version);
            items.saveAll(changed);
        });

        audit.record(editor.actor().entry(AuditOperation.CHECKLIST_TEMPLATE_RULES_BOUND, resource(template, ordinal),
                "Checklist template \"" + template.getSlug() + "\" version " + ordinal + ": rules set on "
                        + changed.size() + (changed.size() == 1 ? " line — " : " lines — ")
                        + String.join("; ", described.subList(0, Math.min(described.size(), AUDITED_LINES)))
                        + (described.size() > AUDITED_LINES
                                ? "; and " + (described.size() - AUDITED_LINES) + " more"
                                : "")
                        + "."));
        return versionView(template, version.getId());
    }

    /**
     * Derives a new draft from a published version without a new file: the same workbook, the same
     * layout, the same items under the same keys — for a change of binding or of evidence, which a
     * published version may never receive in place (§3, step 6).
     */
    public ChecklistVersionView derive(String slug, int ordinal, String label, Editor editor) {
        String versionLabel = BoundedText.optional(label, MAX_LABEL, "The version's label");
        ChecklistTemplateEntity template = requireTemplate(slug);
        ChecklistTemplateVersionEntity source = requireVersion(template, ordinal);
        if (TemplateVersionStatus.ofStored(source.getStatus()) != TemplateVersionStatus.PUBLISHED) {
            throw new ChecklistConflict(Cause.TEMPLATE_NOT_PUBLISHED, "Version " + ordinal + " of \""
                    + template.getSlug() + "\" is " + source.getStatus() + ": a new version is derived from a published one.");
        }
        List<ChecklistItemEntity> copied = items.findByVersionIdOrderByPositionAsc(source.getId());
        Instant now = clock.instant();

        ChecklistTemplateVersionEntity derived = arbitrated(template.getSlug(), () -> transactions.execute(status -> {
            requireNoDraft(template);
            ChecklistTemplateVersionEntity version = newVersion(template, versionLabel, editor, now);
            version.setSourceBytes(source.getSourceBytes());
            version.setSourceSha256(source.getSourceSha256());
            version.setSourceSize(source.getSourceSize());
            version.setLayout(source.getLayout());
            version.setOffersNotApplicable(source.isOffersNotApplicable());
            version.setPreviousVersionId(source.getId());
            version.setDerivedFromVersionId(source.getId());
            ChecklistTemplateVersionEntity saved = versions.save(version);
            items.saveAll(copied.stream().map(item -> copy(item, saved.getId())).toList());
            return saved;
        }));

        audit.record(editor.actor().entry(AuditOperation.CHECKLIST_TEMPLATE_DERIVED,
                resource(template, derived.getOrdinal()),
                "Checklist template \"" + template.getSlug() + "\": version " + derived.getOrdinal()
                        + " derived as a draft from version " + ordinal + ", workbook sha256 "
                        + source.getSourceSha256() + ", " + copied.size() + " items."));
        return versionView(template, derived.getId());
    }

    /**
     * Publishes a draft: from now on, what projects open their checklists on. Immutable once done.
     *
     * @param reviewedRevision the revision the publisher read — a draft edited since is refused
     * @throws ChecklistConflict {@code checklist-template-not-draft}, {@code checklist-template-no-layout},
     *     {@code checklist-template-changed} (edited since the review), or {@code checklist-four-eyes} — with
     *     four-eyes on, the publisher is one of its authors (409)
     */
    public ChecklistVersionView publish(String slug, int ordinal, Integer reviewedRevision, Editor editor) {
        if (reviewedRevision == null) {
            throw new InvalidInputException("State the revision you reviewed — the version's \"revision\": what is "
                    + "published is what somebody has read.");
        }
        ChecklistTemplateEntity template = requireTemplate(slug);
        ChecklistTemplateVersionEntity version = requireDraft(requireVersion(template, ordinal), "be published");
        requireLayout(version, "publishing it");
        requireSeen(template, version, reviewedRevision, "publishing it");
        boolean fourEyes = requireAnotherPerson(template, version, editor, "published");
        Instant now = clock.instant();

        transactions.executeWithoutResult(status -> requireStill(versions.publish(version.getId(), reviewedRevision,
                TemplateVersionStatus.DRAFT.wireName(), TemplateVersionStatus.PUBLISHED.wireName(), now,
                editor.username()), version));

        audit.record(editor.actor().entry(AuditOperation.CHECKLIST_TEMPLATE_PUBLISHED, resource(template, ordinal),
                "Checklist template \"" + template.getSlug() + "\" version " + ordinal + " published, workbook sha256 "
                        + version.getSourceSha256() + "; four-eyes " + (fourEyes
                                ? "required, and the publisher is none of its authors (" + authorNames(version) + ")"
                                : "not required") + "."));
        return versionView(template, version.getId());
    }

    /**
     * Retires a published version — no new checklist opens on it, every checklist on it stays
     * readable — or sets a draft aside. With four-eyes on, a published version is retired by
     * somebody who did not write it; a draft is set aside by anybody who may write templates.
     */
    public ChecklistVersionView retire(String slug, int ordinal, Editor editor) {
        ChecklistTemplateEntity template = requireTemplate(slug);
        ChecklistTemplateVersionEntity version = requireVersion(template, ordinal);
        TemplateVersionStatus from = TemplateVersionStatus.ofStored(version.getStatus());
        if (from == TemplateVersionStatus.RETIRED) {
            throw new ChecklistConflict(Cause.TEMPLATE_RETIRED, "Version " + ordinal + " of \"" + template.getSlug()
                    + "\" is already retired.");
        }
        boolean published = from == TemplateVersionStatus.PUBLISHED;
        boolean fourEyes = published && requireAnotherPerson(template, version, editor, "retired");
        Instant now = clock.instant();

        transactions.executeWithoutResult(status -> requireStill(versions.retire(version.getId(), version.getRevision(),
                from.wireName(), TemplateVersionStatus.RETIRED.wireName(), now, editor.username()), version));

        AuditLogService.Record entry = editor.actor().entry(AuditOperation.CHECKLIST_TEMPLATE_RETIRED,
                resource(template, ordinal), published
                        ? "Checklist template \"" + template.getSlug() + "\" version " + ordinal
                                + " retired: no new checklist opens on it; four-eyes "
                                + (fourEyes ? "required" : "not required") + "."
                        : "Checklist template \"" + template.getSlug() + "\" version " + ordinal
                                + ", a draft never published, set aside.");
        audit.record(published ? entry.signalling(SecurityEventType.CHECKLIST_TEMPLATE_CHANGED) : entry);
        return versionView(template, version.getId());
    }

    // ------------------------------------------------------------------ four-eyes

    /**
     * Refuses an author of the version as the one publishing or retiring it, when four-eyes is on.
     *
     * @return whether the rule applied, which the audit entry states
     */
    private boolean requireAnotherPerson(ChecklistTemplateEntity template, ChecklistTemplateVersionEntity version,
            Editor editor, String act) {
        if (!settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED)) {
            return false;
        }
        if (editor.wrote(forms.authors(version.getDraftAuthors()))) {
            throw new ChecklistConflict(Cause.FOUR_EYES, "Four-eyes approval: version " + version.getOrdinal() + " of \""
                    + template.getSlug() + "\" was written by " + authorNames(version) + ", so it has to be " + act
                    + " by somebody else.");
        }
        return true;
    }

    private String authorNames(ChecklistTemplateVersionEntity version) {
        return forms.authors(version.getDraftAuthors()).stream().map(DraftAuthor::username)
                .collect(Collectors.joining(", "));
    }

    private static List<DraftAuthor> withAuthor(List<DraftAuthor> authors, Editor editor) {
        if (authors.stream().anyMatch(author -> author.accountId() == editor.accountId())) {
            return authors;
        }
        List<DraftAuthor> more = new ArrayList<>(authors);
        more.add(new DraftAuthor(editor.accountId(), editor.username()));
        return more;
    }

    // ------------------------------------------------------------------ parsing

    private static String requireSlug(String slug) {
        String value = slug == null ? "" : slug.strip();
        if (!SLUG.matcher(value).matches()) {
            throw new InvalidInputException("A template's slug is 1 to 64 lowercase letters, digits and inner hyphens"
                    + (value.isEmpty() ? "." : "; \"" + BoundedText.clip(value, 70) + "\" is not one."));
        }
        return value;
    }

    /** A layout as the importer stated it, refused in words where it cannot be one. */
    private static ChecklistLayout parse(ChecklistLayoutForm form) {
        if (form == null) {
            throw new InvalidInputException("A layout is required: the sheet, the columns, the item rows and the "
                    + "answer words.");
        }
        if (form.firstItemRow() == null || form.lastItemRow() == null) {
            throw new InvalidInputException("Name the first and the last item rows.");
        }
        if (form.answers() == null) {
            throw new InvalidInputException("Map the template's answer words to yes and no.");
        }
        Map<ChecklistColumn, String> columns = new EnumMap<>(ChecklistColumn.class);
        (form.columns() == null ? Map.<String, String>of() : form.columns()).forEach((name, letters) ->
                columns.put(named(ChecklistColumn.values(), ChecklistColumn::wireName, name, "column"), letters));
        Map<HeaderCell.Field, HeaderCell> header = new EnumMap<>(HeaderCell.Field.class);
        (form.header() == null ? Map.<String, ChecklistLayoutForm.HeaderCellForm>of() : form.header()).forEach((name, cell) -> {
            HeaderCell.Field field = named(HeaderCell.Field.values(), HeaderCell.Field::wireName, name, "header entry");
            if (cell == null) {
                throw new InvalidInputException("The " + field.wireName() + " header entry names no cells.");
            }
            header.put(field, new HeaderCell(cellOf(cell.label(), field, "label"), cellOf(cell.value(), field, "value")));
        });
        String notApplicable = form.answers().notApplicable();
        AnswerWords answers = new AnswerWords(form.answers().yes(), form.answers().no(),
                notApplicable == null || notApplicable.isBlank() ? Optional.empty() : Optional.of(notApplicable));
        return new ChecklistLayout(form.sheet(), columns, form.firstItemRow(), form.lastItemRow(), header, answers);
    }

    private static <E> E named(E[] values, Function<E, String> wireName, String name, String what) {
        String wanted = name == null ? "" : name.strip().toLowerCase(Locale.ROOT);
        return Arrays.stream(values).filter(value -> wireName.apply(value).equals(wanted)).findFirst()
                .orElseThrow(() -> new InvalidInputException("\"" + BoundedText.clip(String.valueOf(name), 40)
                        + "\" is no " + what + " of a layout; one of "
                        + Arrays.stream(values).map(wireName).collect(Collectors.joining(", ")) + "."));
    }

    private static CellRef cellOf(String reference, HeaderCell.Field field, String which) {
        return CellRef.parse(reference).orElseThrow(() -> new InvalidInputException("The " + field.wireName()
                + " header's " + which + " cell is \"" + BoundedText.clip(String.valueOf(reference), 20)
                + "\", which is no cell — a column's letters and a row, B3."));
    }

    private static List<VersionPairing.ManualPair> parsePairs(List<ChecklistItemPair> requested) {
        if (requested == null) {
            throw new InvalidInputException("State the pairs — an empty list clears them.");
        }
        List<VersionPairing.ManualPair> pairs = new ArrayList<>();
        for (ChecklistItemPair pair : requested) {
            if (pair == null) {
                throw new InvalidInputException("A pair names the added item and the removed one; one of them is empty.");
            }
            pairs.add(new VersionPairing.ManualPair(keyOf(pair.added(), "added"), keyOf(pair.removed(), "removed")));
        }
        return pairs;
    }

    /** A key as the preview shows it: the two forms {@code ItemKey} derives, and nothing a caller writes. */
    private static ItemKey keyOf(String value, String side) {
        String key = value == null ? "" : value.strip();
        if (!(key.startsWith("id:") || key.startsWith("text:")) || key.length() > MAX_KEY) {
            throw new InvalidInputException("A pair's " + side + " item is named by its key as the preview shows it, "
                    + "\"text:…\" or \"id:…\"; \"" + BoundedText.clip(key, 40) + "\" is not one.");
        }
        return new ItemKey(key);
    }

    /**
     * The requirements a request states, by line key, refused in words where one cannot be: the
     * requirement's own record bounds the validity and refuses one on a line asking for no proof.
     */
    private static Map<String, EvidenceRequirement> parseEvidence(List<ChecklistItemEvidence> requested) {
        if (requested == null || requested.isEmpty()) {
            throw new InvalidInputException("Name the lines whose evidence requirement to set — \"items\", each with "
                    + "its \"itemKey\" and its \"evidenceKind\".");
        }
        Map<String, EvidenceRequirement> wanted = new LinkedHashMap<>();
        for (ChecklistItemEvidence line : requested) {
            if (line == null || line.itemKey() == null || line.itemKey().isBlank()) {
                throw new InvalidInputException("Each line is named by its \"itemKey\", as the version shows it; one "
                        + "is empty.");
            }
            String key = line.itemKey().strip();
            if (key.length() > MAX_KEY) {
                throw new InvalidInputException("A line's key is at most " + MAX_KEY + " characters; \""
                        + BoundedText.clip(key, 40) + "\" is longer.");
            }
            EvidenceRequirement evidence = new EvidenceRequirement(EvidenceRequirement.Kind.parse(line.evidenceKind()),
                    Optional.ofNullable(line.evidenceValidityMonths()));
            if (wanted.put(key, evidence) != null) {
                throw new InvalidInputException("The line \"" + BoundedText.clip(key, 60) + "\" is named twice.");
            }
        }
        return wanted;
    }

    /**
     * The rules a request binds, by line key — empty to unbind — each read by the domain. A line named
     * twice is refused: which of two rules was meant is not the service's to guess.
     */
    private Map<String, Optional<ChecklistRule>> parseRules(List<ChecklistItemRule> requested) {
        if (requested == null || requested.isEmpty()) {
            throw new InvalidInputException("Name the lines whose rule to bind — \"items\", each with its \"itemKey\" "
                    + "and its \"rule\", or a null rule to unbind the line.");
        }
        Map<String, Optional<ChecklistRule>> wanted = new LinkedHashMap<>();
        for (ChecklistItemRule line : requested) {
            if (line == null || line.itemKey() == null || line.itemKey().isBlank()) {
                throw new InvalidInputException("Each line is named by its \"itemKey\", as the version shows it; one "
                        + "is empty.");
            }
            String key = line.itemKey().strip();
            if (key.length() > MAX_KEY) {
                throw new InvalidInputException("A line's key is at most " + MAX_KEY + " characters; \""
                        + BoundedText.clip(key, 40) + "\" is longer.");
            }
            Optional<ChecklistRule> rule = line.rule() == null ? Optional.empty() : Optional.of(forms.rule(line.rule()));
            if (wanted.put(key, rule) != null) {
                throw new InvalidInputException("The line \"" + BoundedText.clip(key, 60) + "\" is named twice.");
            }
        }
        return wanted;
    }

    private static String describe(EvidenceRequirement evidence) {
        String asked = switch (evidence.kind()) {
            case NONE -> "asks for no proof";
            case LINK_OR_FILE -> "asks for a link or a file";
            case FILE -> "asks for a file";
        };
        return asked + evidence.validityMonths().map(months -> ", holding " + months + (months == 1 ? " month" : " months"))
                .orElse("");
    }

    // ------------------------------------------------------------------ rows

    private ChecklistTemplateEntity requireTemplate(String slug) {
        return templates.findBySlug(slug == null ? "" : slug.strip())
                .orElseThrow(() -> new NotFoundException("No checklist template \"" + BoundedText.clip(String.valueOf(slug), 70)
                        + "\"."));
    }

    private ChecklistTemplateVersionEntity requireVersion(ChecklistTemplateEntity template, int ordinal) {
        return versions.findByTemplateIdAndOrdinal(template.getId(), ordinal)
                .orElseThrow(() -> new NotFoundException("Checklist template \"" + template.getSlug() + "\" has no version "
                        + ordinal + "."));
    }

    private static ChecklistTemplateVersionEntity requireDraft(ChecklistTemplateVersionEntity version, String act) {
        if (TemplateVersionStatus.ofStored(version.getStatus()) != TemplateVersionStatus.DRAFT) {
            throw new ChecklistConflict(Cause.TEMPLATE_NOT_DRAFT, "Version " + version.getOrdinal() + " is "
                    + version.getStatus()
                    + ": only a draft can " + act + ". A change to a published version is a new version, derived from it.");
        }
        return version;
    }

    private static void requireLayout(ChecklistTemplateVersionEntity version, String act) {
        if (version.getLayout() == null) {
            throw new ChecklistConflict(Cause.TEMPLATE_NO_LAYOUT, "Version " + version.getOrdinal()
                    + " has no confirmed layout, so no item: "
                    + "confirm its layout before " + act + ".");
        }
    }

    private void requireNoDraft(ChecklistTemplateEntity template) {
        if (versions.existsByTemplateIdAndStatus(template.getId(), TemplateVersionStatus.DRAFT.wireName())) {
            throw new ChecklistConflict(Cause.TEMPLATE_HAS_DRAFT, "Checklist template \"" + template.getSlug()
                    + "\" already has a draft: publish "
                    + "it or set it aside before making another.");
        }
    }

    /** The conditional update's answer: nothing matched means somebody else changed the version first. */
    private static void requireStill(int updated, ChecklistTemplateVersionEntity version) {
        if (updated != 1) {
            throw new ChecklistConflict(Cause.TEMPLATE_CHANGED, "Version " + version.getOrdinal()
                    + " changed while this was being done — "
                    + "edited, published or retired by somebody else. Read it again.");
        }
    }

    /**
     * A new draft, arbitrated by the keys: the slug is unique, and so is the number within a
     * template, so of two drafts made at once one insert fails.
     *
     * <p><b>Read as "taken" only once the committed rows say so.</b> A statement can fail for other
     * reasons — a lock timeout, a dropped connection — and on SQLite a key's refusal is not even a
     * {@link DataIntegrityViolationException}. So whatever failed, the transaction rolls back, the
     * rows are asked, and the failure is answered as the draft somebody else made only when there is
     * one; otherwise it is the failure it was.
     */
    private <T> T arbitrated(String slug, Supplier<T> write) {
        try {
            return write.get();
        } catch (ChecklistConflict | InvalidInputException | NotFoundException refusal) {
            throw refusal;
        } catch (RuntimeException failed) {
            Optional<ChecklistTemplateEntity> template = templates.findBySlug(slug);
            if (template.isPresent()) {
                requireNoDraft(template.get());
            }
            throw failed;
        }
    }

    private ChecklistTemplateVersionEntity newVersion(ChecklistTemplateEntity template, String label, Editor editor,
            Instant now) {
        ChecklistTemplateVersionEntity version = new ChecklistTemplateVersionEntity();
        version.setTemplateId(template.getId());
        version.setOrdinal(versions.lastOrdinal(template.getId()) + 1);
        version.setLabel(label);
        version.setStatus(TemplateVersionStatus.DRAFT.wireName());
        version.setRevision(1);
        version.setDraftAuthors(forms.authors(List.of(new DraftAuthor(editor.accountId(), editor.username()))));
        version.setImportedAt(now);
        version.setImportedBy(editor.username());
        return version;
    }

    private Workbook stored(ChecklistTemplateVersionEntity version) {
        // The file was read under the ceiling in force when it was imported; a ceiling lowered since
        // must not make a stored template unreadable.
        return Workbook.read(version.getSourceBytes(), Math.max(maxWorkbookBytes, version.getSourceBytes().length));
    }

    private void replaceItems(long versionId, List<ChecklistItem> read) {
        items.deleteByVersion(versionId);
        items.saveAll(read.stream().map(item -> entity(item, versionId)).toList());
    }

    private static ChecklistItemEntity entity(ChecklistItem item, long versionId) {
        ChecklistItemEntity row = new ChecklistItemEntity();
        row.setVersionId(versionId);
        row.setItemKey(item.key().value());
        row.setPosition(item.position());
        row.setDomain(item.domain());
        row.setObjective(item.objective());
        row.setControl(item.control());
        row.setContact(item.contact());
        row.setKpi(item.kpi());
        row.setContentDigest(item.contentDigest());
        row.setSheetRow(item.row());
        row.setEvidenceKind(item.evidence().kind().wireName());
        row.setEvidenceValidityMonths(item.evidence().validityMonths().orElse(null));
        row.setBoundRule(item.boundRule().orElse(null));
        return row;
    }

    private static ChecklistItemEntity copy(ChecklistItemEntity item, long versionId) {
        ChecklistItemEntity row = new ChecklistItemEntity();
        row.setVersionId(versionId);
        row.setItemKey(item.getItemKey());
        row.setPosition(item.getPosition());
        row.setDomain(item.getDomain());
        row.setObjective(item.getObjective());
        row.setControl(item.getControl());
        row.setContact(item.getContact());
        row.setKpi(item.getKpi());
        row.setContentDigest(item.getContentDigest());
        row.setSheetRow(item.getSheetRow());
        row.setEvidenceKind(item.getEvidenceKind());
        row.setEvidenceValidityMonths(item.getEvidenceValidityMonths());
        row.setBoundRule(item.getBoundRule());
        return row;
    }

    /** A stored item as the domain reads it. Its key, evidence and rule were written from the domain's. */
    static ChecklistItem domain(ChecklistItemEntity item) {
        EvidenceRequirement evidence = new EvidenceRequirement(
                EvidenceRequirement.Kind.valueOf(item.getEvidenceKind().toUpperCase(Locale.ROOT)),
                Optional.ofNullable(item.getEvidenceValidityMonths()));
        return new ChecklistItem(new ItemKey(item.getItemKey()), item.getPosition(), item.getDomain(), item.getObjective(),
                item.getControl(), item.getContact(), item.getKpi(), item.getSheetRow(), evidence,
                Optional.ofNullable(item.getBoundRule()));
    }

    /**
     * The items a layout has just read, each asking for the proof its line already asked for and
     * measured by the rule it was already bound to: the draft's own when the line was read before,
     * else the previous version's line under the same key.
     *
     * <p><b>Why not every line as {@code none} and unbound, as the workbook says.</b> No column of the
     * workbook states a requirement or a rule, so what the reader returns is always {@code none} and
     * unbound, and both are part of the digest. Read as the workbook says, confirming a layout again
     * would silently drop every requirement and every binding a lead had set on the draft, and a new
     * workbook imported over a version that asked for proofs or measured its lines would make each such
     * line <em>changed</em> — every project's answer on it waiting for a confirmation nobody meant to
     * ask for, and nothing measured or asked of it any more.
     */
    private List<ChecklistItem> keepingEvidence(ChecklistTemplateVersionEntity version, List<ChecklistItem> read) {
        Map<ItemKey, ChecklistItem> set = new HashMap<>();
        if (version.getPreviousVersionId() != null) {
            itemsOf(version.getPreviousVersionId()).forEach(item -> set.put(item.key(), item));
        }
        asRead(version).forEach(item -> set.put(item.key(), item));
        return read.stream()
                .map(item -> Optional.ofNullable(set.get(item.key()))
                        .map(before -> item.withEvidence(before.evidence()).withBoundRule(before.boundRule()))
                        .orElse(item))
                .toList();
    }

    private List<ChecklistItem> itemsOf(long versionId) {
        return items.findByVersionIdOrderByPositionAsc(versionId).stream().map(ChecklistTemplateService::domain).toList();
    }

    /**
     * A draft's items as its layout read them: an item paired by hand is stored under the previous
     * version's key, and goes back to its own for the pairing to be made again.
     */
    private List<ChecklistItem> asRead(ChecklistTemplateVersionEntity version) {
        Map<ItemKey, ItemKey> readKeyOf = readKeys(version);
        return itemsOf(version.getId()).stream()
                .map(item -> Optional.ofNullable(readKeyOf.get(item.key())).map(item::withKey).orElse(item))
                .toList();
    }

    /** For each key an item was stored under by a pair, the key its layout read it with. */
    private Map<ItemKey, ItemKey> readKeys(ChecklistTemplateVersionEntity version) {
        Map<ItemKey, ItemKey> readKeyOf = new HashMap<>();
        forms.pairs(version.getItemPairs()).forEach(pair -> readKeyOf.put(pair.removed(), pair.added()));
        return readKeyOf;
    }

    private VersionPairing pairingOf(ChecklistTemplateVersionEntity version) {
        List<ChecklistItem> previous = version.getPreviousVersionId() == null
                ? List.of()
                : itemsOf(version.getPreviousVersionId());
        return VersionPairing.of(previous, asRead(version), forms.pairs(version.getItemPairs()));
    }

    private int ordinalOf(long versionId) {
        return versions.findById(versionId).map(ChecklistTemplateVersionEntity::getOrdinal)
                .orElseThrow(() -> new IllegalStateException("Template version " + versionId + " is gone."));
    }

    private static String resource(ChecklistTemplateEntity template, int ordinal) {
        return template.getSlug() + "/" + ordinal;
    }

    // ------------------------------------------------------------------ views

    private ChecklistTemplateView view(ChecklistTemplateEntity template) {
        List<ChecklistTemplateVersionSummary> rows = versions.summariesOf(template.getId());
        Map<Long, Integer> ordinals = ordinals(rows);
        return new ChecklistTemplateView(template.getId(), template.getSlug(), template.getName(), template.getCreatedAt(),
                template.getCreatedBy(), rows.stream().map(row -> summary(row, ordinals)).toList());
    }

    private ChecklistVersionSummary summary(ChecklistTemplateEntity template, long versionId) {
        List<ChecklistTemplateVersionSummary> rows = versions.summariesOf(template.getId());
        Map<Long, Integer> ordinals = ordinals(rows);
        return rows.stream().filter(row -> row.id() == versionId).findFirst()
                .map(row -> summary(row, ordinals))
                .orElseThrow(() -> new IllegalStateException("Template version " + versionId + " is gone."));
    }

    private ChecklistVersionView versionView(ChecklistTemplateEntity template, long versionId) {
        ChecklistVersionSummary summary = summary(template, versionId);
        ChecklistTemplateVersionEntity version = versions.findById(versionId)
                .orElseThrow(() -> new IllegalStateException("Template version " + versionId + " is gone."));
        List<ChecklistItemView> lines = items.findByVersionIdOrderByPositionAsc(versionId).stream()
                .map(ChecklistItemView::of).toList();
        return new ChecklistVersionView(template.getSlug(), template.getName(), summary,
                Optional.ofNullable(version.getLayout()).map(forms::layout).map(ChecklistLayoutForm::of).orElse(null),
                lines, forms.pairs(version.getItemPairs()).stream()
                        .map(pair -> new ChecklistItemPair(pair.added().value(), pair.removed().value())).toList());
    }

    private static Map<Long, Integer> ordinals(List<ChecklistTemplateVersionSummary> rows) {
        Map<Long, Integer> ordinals = new LinkedHashMap<>();
        rows.forEach(row -> ordinals.put(row.id(), row.ordinal()));
        return ordinals;
    }

    private ChecklistVersionSummary summary(ChecklistTemplateVersionSummary row, Map<Long, Integer> ordinals) {
        return new ChecklistVersionSummary(row.id(), row.ordinal(), row.label(), row.status(), row.revision(),
                row.sourceSha256(), row.sourceSize(), row.layout() != null, row.offersNotApplicable(),
                row.itemCount() == null ? 0 : row.itemCount(),
                row.previousVersionId() == null ? null : ordinals.get(row.previousVersionId()),
                row.derivedFromVersionId() == null ? null : ordinals.get(row.derivedFromVersionId()),
                forms.authors(row.draftAuthors()).stream().map(DraftAuthor::username).toList(),
                row.importedAt(), row.importedBy(), row.publishedAt(), row.publishedBy(), row.retiredAt(),
                row.retiredBy());
    }

    private static ChecklistTemplatePreview.ProposedLayout proposed(LayoutProposal proposal) {
        Map<String, String> columns = new LinkedHashMap<>();
        proposal.columns().forEach((column, letters) -> columns.put(column.wireName(), letters));
        Map<String, ChecklistLayoutForm.HeaderCellForm> header = new LinkedHashMap<>();
        proposal.header().forEach((field, cell) -> header.put(field.wireName(),
                new ChecklistLayoutForm.HeaderCellForm(cell.label().toString(), cell.value().toString())));
        return new ChecklistTemplatePreview.ProposedLayout(proposal.sheet(), proposal.columnHeaderRow().orElse(null),
                proposal.firstItemRow().orElse(null), proposal.lastItemRow().orElse(null), columns, header,
                proposal.answerValues());
    }

    private static ChecklistTemplatePreview.PairingChange change(VersionPairing.Change change, Map<ItemKey, ItemKey> readKeyOf) {
        return switch (change) {
            case VersionPairing.Unchanged unchanged -> new ChecklistTemplatePreview.PairingChange("unchanged", false,
                    unchanged.next().key().value(), unchanged.next().row(), unchanged.next().control(),
                    unchanged.previous().key().value(), unchanged.previous().row(), unchanged.previous().control());
            case VersionPairing.Changed changed -> new ChecklistTemplatePreview.PairingChange("changed",
                    changed.pairedByHand(),
                    // Paired by hand, the item carries the old key; the pair named it by the one it was read with.
                    changed.pairedByHand()
                            ? readKeyOf.getOrDefault(changed.next().key(), changed.next().key()).value()
                            : changed.next().key().value(),
                    changed.next().row(),
                    changed.next().control(), changed.previous().key().value(), changed.previous().row(),
                    changed.previous().control());
            case VersionPairing.Added added -> new ChecklistTemplatePreview.PairingChange("added", false,
                    added.next().key().value(), added.next().row(), added.next().control(), null, null, null);
            case VersionPairing.Removed removed -> new ChecklistTemplatePreview.PairingChange("removed", false, null, null,
                    null, removed.previous().key().value(), removed.previous().row(), removed.previous().control());
        };
    }

    /**
     * The revision the writer read is the one being changed. The conditional update alone compares
     * with the revision this request read a moment earlier, which only orders two requests: two leads
     * editing one draft from the same screen would each overwrite the other's layout or pairs, silently,
     * and the second would never have seen the first's work.
     */
    private static void requireSeen(ChecklistTemplateEntity template, ChecklistTemplateVersionEntity version,
            Integer seenRevision, String doing) {
        if (seenRevision == null) {
            throw new InvalidInputException("State the revision you read — the version's \"revision\": a draft is "
                    + "changed from what somebody has seen.");
        }
        if (!version.getRevision().equals(seenRevision)) {
            throw new ChecklistConflict(Cause.TEMPLATE_CHANGED, "Version " + version.getOrdinal() + " of \""
                    + template.getSlug() + "\" has "
                    + "changed since revision " + seenRevision + " — it is at revision " + version.getRevision()
                    + ". Read it again before " + doing + ".");
        }
    }
}
