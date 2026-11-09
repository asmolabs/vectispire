package com.asmolabs.vectispire.core.rules;

import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.rules.InvalidRuleSetException;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.StoredFile;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.TriageImpact;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.UploadedFile;
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.scanning.BundledRules;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.rules.persistence.SemgrepRuleSetRepository;
import com.asmolabs.vectispire.core.rules.persistence.SemgrepRuleSetEntity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Uploaded Semgrep rule sets: storing them, activating one, and serving them to executors.
 *
 * <p><b>Why this exists rather than the environment variable alone.</b> {@code
 * VECTISPIRE_SEMGREP_RULES_DIR} is read by the process that scans, and the scanner is shared
 * between the built-in worker and every remote agent. The directory therefore has to be
 * provisioned on each agent's filesystem, and the control plane has no way to check that it
 * was. Two agents, one provisioned and one not, taking turns on the same target make the SAST
 * backlog resolve and reappear with each turn — silently, because the step <em>ran</em> both
 * times. A set stored here and fetched by every executor removes that asymmetry.
 *
 * <p>The environment variable is not withdrawn: it stays the right answer for a
 * single-instance deployment that already manages a volume. The precedence between the two is
 * settled in the scanner, and stated there.
 */
@Service
public class RuleSetService {

    private static final TypeReference<List<StoredFile>> FILES = new TypeReference<>() {};

    private static final int MAX_NAME_LENGTH = 255;

    private final SemgrepRuleSetRepository ruleSets;
    private final IssueCatalog issues;
    private final ObjectMapper json;
    private final Clock clock;

    public RuleSetService(SemgrepRuleSetRepository ruleSets, IssueCatalog issues, ObjectMapper json, Clock clock) {
        this.ruleSets = ruleSets;
        this.issues = issues;
        this.json = json;
        this.clock = clock;
    }

    /**
     * Stores an upload. <b>Does not activate it.</b>
     *
     * <p>The two steps are separate because activation is the destructive one: it changes what
     * the next scan looks for, and a rule that disappears takes its open issues with it. An
     * operator uploads, reads what activation would cost, and then decides.
     */
    @Transactional
    public SemgrepRuleSetEntity store(List<UploadedFile> files, String name, String uploadedBy) {
        String label = name == null ? "" : name.trim();
        if (label.isEmpty()) {
            throw new InvalidRuleSetException("A rule set needs a name.");
        }
        // The column is 255; past it the insert failed at the flush, as a 500, after every file
        // had been parsed and hashed.
        if (label.length() > MAX_NAME_LENGTH) {
            throw new InvalidRuleSetException("A rule set's name is at most " + MAX_NAME_LENGTH + " characters.");
        }

        List<StoredFile> stored = RuleSet.accept(files);

        SemgrepRuleSetEntity row = new SemgrepRuleSetEntity();
        row.setName(label);
        row.setFiles(writeFiles(stored));
        row.setContentHash(RuleSet.contentHash(stored));
        row.setRuleCount(RuleSet.ruleIdsOf(stored).size());
        row.setFileCount(stored.size());
        row.setSizeBytes(stored.stream()
                .mapToLong(file -> file.content().getBytes(StandardCharsets.UTF_8).length)
                .sum());
        // `null`, not `false`. See `SemgrepRuleSetRepository`: the unique index is the guard.
        row.setIsActive(null);
        row.setUploadedBy(uploadedBy);
        row.setUploadedAt(clock.instant());
        row.setActivationNote(null);

        return ruleSets.save(row);
    }

    /** Every stored set, newest first, without their content. */
    @Transactional(readOnly = true)
    public List<RuleSetSummary> list() {
        return ruleSets.summaries().stream().map(RuleSetSummary::of).toList();
    }

    /** The active set, or empty when only the bundled rules apply. */
    @Transactional(readOnly = true)
    public Optional<SemgrepRuleSetEntity> active() {
        return ruleSets.findByIsActiveTrue();
    }

    @Transactional(readOnly = true)
    public Optional<SemgrepRuleSetEntity> byId(long id) {
        return ruleSets.findById(id);
    }

    /** A set by the hash an executor holds, for the fetch route. */
    @Transactional(readOnly = true)
    public Optional<SemgrepRuleSetEntity> byHash(String contentHash) {
        return ruleSets.findFirstByContentHashOrderByIdAsc(contentHash);
    }

    /**
     * What an executor fetches by the hash it holds: the hash, and the rules decoded.
     *
     * <p>One call rather than {@link #byHash} then {@link #filesOf}, so the row stays in this
     * layer: the fetch route only ever needed what the row says, never the row.
     */
    public record Content(String contentHash, List<StoredFile> files) {}

    public Optional<Content> contentByHash(String contentHash) {
        return byHash(contentHash).map(row -> new Content(row.getContentHash(), filesOf(row)));
    }

    /** The rules of a stored set, decoded. */
    public List<StoredFile> filesOf(SemgrepRuleSetEntity row) {
        try {
            return json.readValue(row.getFiles(), FILES);
        } catch (JsonProcessingException corrupt) {
            // Distinct from "no set is active": falling back to the bundled rule here would
            // silently narrow what every scan looks for, which is the failure this whole
            // feature exists to prevent.
            throw new InvalidRuleSetException("The stored rules of set " + row.getId() + " cannot be read back.");
        }
    }

    /**
     * What activating this set would do to the existing backlog.
     *
     * <p><b>The answer an operator has to see before clicking.</b> A rule id enters an issue's
     * fingerprint: a rule absent from the new set stops being found, its issues resolve on the
     * next scan, and their triage — justifications, review dates, who decided — goes with them.
     * Nothing errors, and the dashboard looks better afterwards.
     *
     * <p>Counted from the open SAST issues that exist right now rather than from the previously
     * uploaded set, because the backlog is the authority on what has something to lose: rules
     * also arrive from the bundled tree and from {@code VECTISPIRE_SEMGREP_RULES_DIR}. The bundled
     * rules run beside whichever set is active, so their issues lose nothing and are left out:
     * counted, they made an activation announce the resolution of issues it never resolves — and,
     * since activation refuses an announced loss, demand that it be accepted. The operator's
     * directory cannot be read from here and stays counted: an overstatement the operator accepts
     * with its number, never a loss nobody was told about.
     */
    @Transactional(readOnly = true)
    public TriageImpact impactOf(SemgrepRuleSetEntity candidate) {
        return impactOfReplacingWith(RuleSet.ruleIdsOf(filesOf(candidate)));
    }

    /** What returning to the bundled rules alone would do to the backlog: the active set's rules leave. */
    @Transactional(readOnly = true)
    public TriageImpact deactivationImpact() {
        return impactOfReplacingWith(Set.of());
    }

    private TriageImpact impactOfReplacingWith(Set<String> uploaded) {
        Set<String> bundled = bundledRuleIds();
        Set<String> current = new LinkedHashSet<>(bundled);
        active().ifPresent(row -> current.addAll(RuleSet.ruleIdsOf(filesOf(row))));
        Set<String> next = new LinkedHashSet<>(bundled);
        next.addAll(uploaded);
        return RuleSet.impact(current, next, openSastIssuesByRule());
    }

    private static Set<String> bundledRuleIds() {
        Set<String> ids = new LinkedHashSet<>();
        BundledRules.expected().stream()
                .filter(path -> path.startsWith("semgrep/"))
                .forEach(path -> ids.addAll(RuleSet.ruleIdsIn(BundledRules.contentOf(path))));
        return ids;
    }

    /**
     * An activation, and the loss it was allowed to cause — none, or exactly the count the caller
     * accepted.
     */
    public record Activation(SemgrepRuleSetEntity activated, TriageImpact accepted) {}

    /**
     * Activates a set, and records what the operator was told it would cost.
     *
     * <p>In one transaction with the deactivation: the unique index makes two active rows
     * impossible, so a half-applied change would leave <em>none</em> active — silently falling
     * back to the bundled rule, which is precisely the outcome this feature exists to prevent.
     *
     * <p><b>An activation that resolves open issues is refused unless the caller names their
     * number</b> ({@link RuleSetLosesIssuesException}). The preview route said how many, and the
     * button went ahead whatever the preview said, or whether anybody read it. The number is read
     * again here, in the transaction that activates, and must equal what the caller accepted: a
     * preview taken before new findings arrived authorises the loss it showed, never more.
     *
     * @param acceptLosing the number of open issues the caller accepts to see resolved; ignored when
     *     the activation resolves none
     */
    @Transactional
    public Activation activate(long id, String note, Long acceptLosing) {
        // 404, not 400: the path names a set that is not there, which is the answer the impact
        // route beside it already gives for the same id. An invalid-rule-set refusal said the
        // request was malformed, and a client retried it with a different body.
        SemgrepRuleSetEntity target = ruleSets
                .findById(id)
                .orElseThrow(() -> new NotFoundException("No rule set with id " + id + "."));

        // What the operator was shown when they confirmed, kept as the activation's record — and a
        // `text` column, so bounded like every other stored text.
        if (note != null && note.length() > BoundedText.TEXT_MAX) {
            throw new InvalidRuleSetException("The activation note is longer than " + BoundedText.TEXT_MAX + " characters.");
        }

        TriageImpact impact = impactOf(target);
        RuleSetLosesIssuesException.refuseUnlessAccepted(impact, acceptLosing, "Activating this rule set");

        ruleSets.deactivateAll();
        ruleSets.activate(target.getId(), note);

        // Re-read rather than mutating the object in hand: the two statements above bypass the
        // persistence context, so the entity loaded before them still says what it said.
        return new Activation(
                ruleSets.findById(id).orElseThrow(() -> new NotFoundException("No rule set with id " + id + ".")),
                impact);
    }

    /**
     * Returns to the bundled rules alone, refused like an activation when the active set's rules
     * leave open issues behind: the bundled rules are a set too, and a narrower one than any
     * uploaded.
     *
     * @return the loss accepted — none, or exactly {@code acceptLosing}
     */
    @Transactional
    public TriageImpact deactivateAll(Long acceptLosing) {
        TriageImpact impact = deactivationImpact();
        RuleSetLosesIssuesException.refuseUnlessAccepted(impact, acceptLosing, "Returning to the bundled rules");
        ruleSets.deactivateAll();
        return impact;
    }

    /**
     * Open SAST issues, counted per rule identifier.
     *
     * <p>Read from the issues alone: an issue carries its own type and identifier, and that
     * identifier <b>is</b> Semgrep's {@code check_id} — the same string, because {@code
     * --no-rewrite-rule-ids} stops Semgrep prefixing it with the rule file's path.
     */
    private Map<String, Long> openSastIssuesByRule() {
        return new HashMap<>(issues.countOpenByIdentifier(IssueState.OPEN.wireName(), FindingType.SAST.wireName()));
    }

    private String writeFiles(List<StoredFile> files) {
        try {
            return json.writeValueAsString(files);
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("A validated rule set could not be serialized", impossible);
        }
    }
}
