package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.rules.InvalidRuleSetException;
import com.asmolabs.zanshin.common.domain.rules.RuleSet.StoredFile;
import com.asmolabs.zanshin.common.domain.rules.RuleSet.TriageImpact;
import com.asmolabs.zanshin.common.domain.rules.RuleSet.UploadedFile;
import com.asmolabs.zanshin.common.domain.rules.RuleSet;
import com.asmolabs.zanshin.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.RuleSetSummary;
import com.asmolabs.zanshin.core.repositories.RuleSets;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.HashMap;
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
 * ZANSHIN_SEMGREP_RULES_DIR} is read by the process that scans, and the scanner is shared
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

    private final RuleSets ruleSets;
    private final Issues issues;
    private final ObjectMapper json;
    private final Clock clock;

    public RuleSetService(RuleSets ruleSets, Issues issues, ObjectMapper json, Clock clock) {
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
        // `null`, not `false`. See `RuleSets`: the unique index is the guard.
        row.setIsActive(null);
        row.setUploadedBy(uploadedBy);
        row.setUploadedAt(clock.instant());
        row.setActivationNote(null);

        return ruleSets.save(row);
    }

    /** Every stored set, newest first, without their content. */
    @Transactional(readOnly = true)
    public List<RuleSetSummary> list() {
        return ruleSets.summaries();
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
     * also arrive from the bundled tree and from {@code ZANSHIN_SEMGREP_RULES_DIR}.
     */
    @Transactional(readOnly = true)
    public TriageImpact impactOf(SemgrepRuleSetEntity candidate) {
        Set<String> current = active().map(row -> RuleSet.ruleIdsOf(filesOf(row))).orElseGet(Set::of);
        return RuleSet.impact(current, RuleSet.ruleIdsOf(filesOf(candidate)), openSastIssuesByRule());
    }

    /**
     * Activates a set, and records what the operator was told it would cost.
     *
     * <p>In one transaction with the deactivation: the unique index makes two active rows
     * impossible, so a half-applied change would leave <em>none</em> active — silently falling
     * back to the bundled rule, which is precisely the outcome this feature exists to prevent.
     */
    @Transactional
    public SemgrepRuleSetEntity activate(long id, String note) {
        SemgrepRuleSetEntity target = ruleSets
                .findById(id)
                .orElseThrow(() -> new InvalidRuleSetException("No rule set with id " + id + "."));

        ruleSets.deactivateAll();
        ruleSets.activate(target.getId(), note);

        // Re-read rather than mutating the object in hand: the two statements above bypass the
        // persistence context, so the entity loaded before them still says what it said.
        return ruleSets.findById(id).orElseThrow(() -> new InvalidRuleSetException("No rule set with id " + id + "."));
    }

    /** Returns to the bundled rules alone. */
    @Transactional
    public void deactivateAll() {
        ruleSets.deactivateAll();
    }

    /**
     * Open SAST issues, counted per rule identifier.
     *
     * <p>Read from the issues alone: an issue carries its own type and identifier, and that
     * identifier <b>is</b> Semgrep's {@code check_id} — the same string, because {@code
     * --no-rewrite-rule-ids} stops Semgrep prefixing it with the rule file's path.
     */
    private Map<String, Long> openSastIssuesByRule() {
        Map<String, Long> counts = new HashMap<>();
        for (Object[] row : issues.countOpenByIdentifier(IssueState.OPEN.wireName(), FindingType.SAST.wireName())) {
            counts.put((String) row[0], ((Number) row[1]).longValue());
        }
        return counts;
    }

    private String writeFiles(List<StoredFile> files) {
        try {
            return json.writeValueAsString(files);
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("A validated rule set could not be serialized", impossible);
        }
    }
}
