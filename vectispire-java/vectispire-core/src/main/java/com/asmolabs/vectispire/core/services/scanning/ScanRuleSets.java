package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import java.util.List;
import java.util.Optional;

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
}
