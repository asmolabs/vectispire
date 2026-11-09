package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The uploaded Semgrep rules, as a scan needs them: which set is active, and a set's files by hash.
 *
 * <p><b>A port, implemented by {@code rules}.</b> The dispatcher and the built-in worker's
 * configuration called {@code RuleSetService} and took its entity back — a layered class holding
 * {@code rules}' {@code SemgrepRuleSetEntity} (a step-5 finding of decision 0028). Worse, once
 * {@code inventory} reads scans through {@code scanning}, a call from {@code scanning} to {@code
 * rules}, which compares its rules with the inventory, closes a cycle. Declared here with the two
 * questions a scan asks, the dependency points from {@code rules} to {@code scanning} (decision 0029).
 */
public interface ScanRuleSets {

    /** The active set's content hash, or empty when only the bundled rules apply. */
    Optional<String> activeHash();

    /**
     * The files of the set with this hash, decoded — or an empty list when no set has it. A stored
     * set that cannot be decoded throws rather than answering empty: falling back to the bundled rule
     * would silently narrow what every scan looks for.
     */
    List<RuleSet.StoredFile> filesOf(String contentHash);

    /**
     * The languages the Semgrep rules of a task carrying this hash read: the bundled rules' and the
     * set's, by their directories ({@code RuleCoverage.languagesRead}). Recorded on the scan when its
     * task is built, so that a checklist judges the scan by the rules it ran with, not by whatever set
     * is active when somebody reads the line (decision 0032 §6).
     *
     * <p>An executor's own {@code VECTISPIRE_SEMGREP_RULES_DIR}, used when no set is active, is on that
     * executor's disk and not here: it is not counted, which can keep a line from passing and never
     * makes one pass.
     *
     * @param contentHash the set the task names, or {@code null} for the bundled rules alone
     */
    Set<Language> languagesRead(String contentHash);
}
