package com.asmolabs.vectispire.common.domain.rules;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An uploaded Semgrep rule set: what is accepted, and what is deliberately not done to it.
 *
 * <p>Vectispire bundles a single rule — the public sets are not redistributable (decision 0006) —
 * so an operator's coverage has to arrive from outside. {@code VECTISPIRE_SEMGREP_RULES_DIR} is
 * one way, and it has a hole this module exists to close: it is read <b>by the process that
 * scans</b>, so every remote agent needs the directory provisioned on its own filesystem and
 * the control plane cannot check that it was. Two agents, one provisioned and one not, take
 * turns on the same target and the SAST backlog resolves and reappears with each turn —
 * silently, because the step <em>ran</em> both times.
 *
 * <h2>Vectispire never parses these rules, and that is a security decision</h2>
 *
 * <p>The obvious implementation reads each file's YAML to count rules and read their ids. It
 * is refused here for a specific reason. Document 03 accepts a YAML parser advisory on the
 * grounds that "the only YAML that path produces is the OpenAPI document Vectispire generates
 * itself: the exponential-time parse needs hostile input, and there is none" — and names what
 * would overturn that decision: "some path in Vectispire starting to parse YAML from elsewhere".
 * <b>This would have been that path.</b>
 *
 * <p>So the bytes are stored verbatim and handed to <b>Semgrep</b>, which has to understand
 * them anyway and does so inside a container with the network cut off, {@code cap_drop: ALL},
 * and memory and PID caps. The rule counting and id extraction below are bounded regular
 * expressions over a size-capped input, used <b>only</b> to tell an operator what they are
 * about to do. Nothing in a scan's correctness depends on them being exhaustive.
 *
 * <h2>The filenames are ours</h2>
 *
 * <p>Uploaded names are recorded for display and never used as paths. Files are written as
 * {@code rule-0001.yaml}, {@code rule-0002.yaml}, … which removes path traversal as a class
 * rather than filtering for it: there is no attacker-controlled path to escape from.
 *
 * <p>This is free because {@code --no-rewrite-rule-ids} is passed to Semgrep. Without that
 * flag Semgrep prefixes every {@code check_id} with the rule file's relative path, so renaming
 * files renames every identifier — which enters an issue's fingerprint, so the whole SAST
 * backlog would resolve and be recreated, triage lost.
 */
public final class RuleSet {

    private RuleSet() {}

    /**
     * Three caps, all load-bearing.
     *
     * <p>The per-file and total limits bound what a bounded regex has to walk and what a
     * request body can carry. The file count bounds the workspace copy: {@code opengrep-rules}
     * is a few thousand files, so the limit sits above that rather than below it.
     */
    public static final int MAX_FILES = 8_000;

    public static final int MAX_FILE_BYTES = 512 * 1024;
    public static final int MAX_TOTAL_BYTES = 32 * 1024 * 1024;

    private static final Pattern YAML_NAME = Pattern.compile("\\.ya?ml$", Pattern.CASE_INSENSITIVE);

    /**
     * Anchored per line, and bounded by the file size cap, so there is no backtracking to
     * worry about.
     */
    private static final Pattern RULE_ID = Pattern.compile("^\\s*-?\\s*id:\\s*[\"']?([A-Za-z0-9._\\-/]+)[\"']?\\s*$");

    /** One uploaded file, as the API receives it. */
    public record UploadedFile(
            /* The operator's name for it. Recorded, displayed, never used as a path. */
            String name,
            String content) {}

    /** A stored file, under the name Vectispire chose. */
    public record StoredFile(
            /* `rule-0001.yaml`. Generated here, never taken from the upload. */
            String path,
            /* The name the operator uploaded, kept so a rule can be traced back. */
            String originalName,
            String content) {}

    /**
     * Validates an upload and returns it under Vectispire's own filenames.
     *
     * <p>Throws rather than filtering silently: an operator who uploaded forty files and got
     * thirty-eight stored would have coverage they believe they have and do not.
     */
    public static List<StoredFile> accept(List<UploadedFile> files) {
        if (files == null || files.isEmpty()) {
            throw new InvalidRuleSetException("No file was uploaded.");
        }
        if (files.size() > MAX_FILES) {
            throw new InvalidRuleSetException("Too many files: " + files.size() + ", the limit is " + MAX_FILES + ".");
        }

        long total = 0;
        List<StoredFile> stored = new ArrayList<>(files.size());

        for (int index = 0; index < files.size(); index++) {
            UploadedFile file = files.get(index);
            String name = file.name() == null ? "" : file.name().trim();
            if (!YAML_NAME.matcher(name).find()) {
                throw new InvalidRuleSetException("\"" + (name.isEmpty() ? "(unnamed)" : name)
                        + "\" is not a YAML file. Semgrep rules are .yaml or .yml.");
            }

            String content = file.content() == null ? "" : file.content();
            int bytes = content.getBytes(StandardCharsets.UTF_8).length;
            if (bytes == 0) {
                throw new InvalidRuleSetException("\"" + name + "\" is empty.");
            }
            if (bytes > MAX_FILE_BYTES) {
                throw new InvalidRuleSetException("\"" + name + "\" is " + bytes + " bytes, over the "
                        + MAX_FILE_BYTES + " limit for one file.");
            }
            total += bytes;
            if (total > MAX_TOTAL_BYTES) {
                throw new InvalidRuleSetException("The upload exceeds " + MAX_TOTAL_BYTES + " bytes in total.");
            }

            // Numbered from one, zero-padded to four: the order is stable, and Semgrep reads
            // the whole directory regardless.
            stored.add(new StoredFile(String.format(Locale.ROOT, "rule-%04d.yaml", index + 1), name, content));
        }
        return List.copyOf(stored);
    }

    /**
     * The rule ids a file declares, by pattern match rather than by parsing.
     *
     * <p><b>Advisory only.</b> A rule whose id is written in a form this does not match is
     * still shipped to Semgrep and still runs; it is only missing from the counts and from the
     * impact warning. That trade is the point — an exhaustive answer would require parsing
     * YAML, which this module refuses to do.
     */
    public static List<String> ruleIdsIn(String content) {
        List<String> ids = new ArrayList<>();
        for (String line : content.split("\n")) {
            Matcher match = RULE_ID.matcher(line);
            if (match.matches()) {
                ids.add(match.group(1));
            }
        }
        return ids;
    }

    /** Every id in a rule set, deduplicated, in encounter order. */
    public static Set<String> ruleIdsOf(List<StoredFile> files) {
        Set<String> ids = new LinkedHashSet<>();
        for (StoredFile file : files) {
            ids.addAll(ruleIdsIn(file.content()));
        }
        return ids;
    }

    /**
     * The identity an executor caches on.
     *
     * <p>Computed over the content and the <em>generated</em> paths, in order — not over the
     * upload's own names, so re-uploading the same rules under different filenames does not
     * invalidate every agent's cache.
     */
    public static String contentHash(List<StoredFile> files) {
        StringBuilder joined = new StringBuilder();
        for (StoredFile file : files) {
            joined.append(file.path()).append(Digests.SEPARATOR).append(file.content()).append(Digests.SEPARATOR);
        }
        return Digests.sha256Hex(joined.toString());
    }

    /**
     * @param losingIssues rule ids that currently have open issues and are absent from the new
     *     set, sorted so the warning reads the same twice and a long list truncates predictably
     */
    public record TriageImpact(List<String> losingIssues, long affectedIssues, int addedRules, int removedRules) {}

    /**
     * What activating a rule set would do to the existing backlog.
     *
     * <p><b>This is the part that needs saying out loud in the interface.</b> A rule id enters
     * an issue's fingerprint, so a rule that disappears takes its issues with it: the next scan
     * does not find them, and they are resolved — with their triage decisions, their
     * justifications, their review dates. A three-click upload makes that destruction reachable
     * by somebody who does not know it.
     *
     * <p>Counted from the issues that are <b>open</b> right now, because a resolved issue has
     * nothing left to lose.
     */
    public static TriageImpact impact(Set<String> current, Set<String> next, Map<String, Long> openIssuesByRuleId) {
        Set<String> losing = new TreeSet<>();
        long affected = 0;

        for (Map.Entry<String, Long> entry : openIssuesByRuleId.entrySet()) {
            if (next.contains(entry.getKey())) {
                continue;
            }
            losing.add(entry.getKey());
            affected += entry.getValue();
        }

        int added = (int) next.stream().filter(id -> !current.contains(id)).count();
        int removed = (int) current.stream().filter(id -> !next.contains(id)).count();

        return new TriageImpact(List.copyOf(losing), affected, added, removed);
    }
}
