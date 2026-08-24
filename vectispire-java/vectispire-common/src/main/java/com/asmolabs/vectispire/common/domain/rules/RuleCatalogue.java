package com.asmolabs.vectispire.common.domain.rules;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Fetching a third-party rule set, and the licence conditions that make it legitimate.
 *
 * <p><b>Vectispire never redistributes these rules.</b> That distinction is the whole of
 * <a href="../../../../../../../../../docs/architecture/decisions/0006-semgrep-rules-written-here.md">decision
 * 0006</a>: the operator instructs Vectispire to fetch, the rules travel from their author to the
 * operator's own installation, and nothing containing them is shipped. Which is why the
 * upstream is a fixed constant here rather than a field somebody can point anywhere.
 *
 * <p><b>One upstream is refused outright.</b> {@code semgrep/semgrep-rules} was relicensed
 * under terms that forbid distributing the rules at all. It is named in {@link #FORBIDDEN} so
 * that a future field, setting or typo cannot reach it — a refusal written in a document is one
 * somebody will work around without knowing there was a reason.
 */
public final class RuleCatalogue {

    /** The fork taken before the relicensing, and the only upstream this fetches. */
    public static final String UPSTREAM = "opengrep/opengrep-rules";

    /**
     * LGPL-2.1 <b>plus a Commons Clause</b>, which is why acceptance is explicit.
     *
     * <p>The clause takes whoever adopts these rules out of open source in the OSI sense. That
     * is a decision for the operator to make knowingly, about rules somebody else wrote — not
     * one Vectispire makes for them by shipping the rules in the box.
     */
    public static final String LICENCE = "LGPL-2.1 with Commons Clause";

    /** Refused however it is spelled, because the licence forbids distribution outright. */
    public static final Set<String> FORBIDDEN = Set.of("semgrep/semgrep-rules");

    /**
     * The pin is a commit, not a tag.
     *
     * <p><b>The upstream publishes no tags at all</b> — only {@code refs/heads/main}. Decision
     * 0006 asked for a pinned tag because it pictured a fetch into a directory at install time;
     * that requirement is unsatisfiable against this repository, and the manual procedure in the
     * README was unsatisfiable for the same reason.
     *
     * <p>A commit is the better pin anyway: a tag can be moved, a SHA cannot. And what actually
     * makes a scan reproducible here is not the ability to fetch the same thing twice — the
     * rules land in the database as an immutable set with its own content hash, and it is that
     * stored copy every later scan uses. The pin's job is provenance: "which rules ran, and
     * where did they come from", answered a year later.
     */
    private static final Pattern COMMIT = Pattern.compile("^[0-9a-f]{40}$");

    /** A YAML file. Whether it is a *rule* is decided by its content, below. */
    private static final Pattern YAML = Pattern.compile("(?i)\\.ya?ml$");

    /**
     * What makes a YAML file a rule file.
     *
     * <p>Decided by content and not by name: the upstream ships test fixtures beside its rules —
     * 88 of them at the commit this was written against — and a name-based exclusion list is one
     * more thing to keep in step with somebody else's repository. A file Semgrep would not accept
     * as a configuration has no business in a rule set.
     *
     * <p><b>Content alone was not enough, and the reason is worth keeping.</b> Ten fixtures in
     * this upstream reach Semgrep as configurations it refuses, and <b>one refused file makes it
     * exit 7 and analyse nothing at all</b> — the whole SAST step produced an empty result on
     * every target, for every scan, until this was found. The ten split into two kinds, and only
     * one of them is detectable by reading the file:
     *
     * <ul>
     *   <li>A Kubernetes {@code ClusterRole} manifest declares {@code rules:} too — that is the
     *       field holding its permissions — so
     *       {@code legacy-api-clusterrole-excessive-permissions.test.yaml} looked like a rule
     *       file. Requiring a rule id settles it: {@code id} is mandatory in Semgrep's schema,
     *       and a {@code ClusterRole}'s rules carry {@code apiGroups} and {@code verbs}.
     *   <li>The other nine are fixtures of the <em>rule-linting</em> rules — {@code
     *       duplicate-id.test.yaml}, {@code empty-message.test.yaml}, {@code
     *       metadata-confidence-incorrect-value.test.yaml}. They are <b>deliberately malformed
     *       rule files</b>, because that is what a fixture for a rule that lints rules has to be.
     *       No amount of reading distinguishes them from a rule file that is merely wrong.
     * </ul>
     *
     * <p>Hence the name check as well, which the first version of this class argued against on
     * the grounds that a name-based exclusion is one more thing to keep in step with somebody
     * else's repository. That argument was right about the cost and wrong about the alternative:
     * {@code .test.yaml} is the upstream's own convention for a fixture, and the content it
     * describes is by design indistinguishable from the thing it tests.
     */
    private static final Pattern DECLARES_RULES = Pattern.compile("(?m)^rules:");

    /** Mandatory in every Semgrep rule; absent from anything that merely borrows the word. */
    private static final Pattern DECLARES_A_RULE_ID = Pattern.compile("(?m)^\\s*-?\\s*id:\\s*\\S");

    /** The upstream's convention for a rule's test input, in the upstream's own filenames. */
    private static final Pattern TEST_FIXTURE = Pattern.compile("(?i)\\.test\\.ya?ml$");

    /**
     * Directories that are not a language, and would otherwise be offered as one.
     *
     * <p>Listed rather than guessed: an unknown top-level directory is more likely to be a new
     * language than a new piece of scaffolding, and offering one too many is a smaller mistake
     * than silently hiding a language somebody needs.
     */
    private static final Set<String> NOT_A_LANGUAGE =
            Set.of(".github", ".pre-commit-hooks", "stats", "scripts", "docs", "template", "libsonnet");

    private RuleCatalogue() {}

    /** A file inside the fetched archive, already stripped of its top-level directory. */
    public record Entry(String path, String content) {}

    /**
     * @param languages how many rule files each top-level directory holds, ordered by name so
     *     two fetches of the same tag present the same list
     * @param licence the text as it stands <b>at this tag</b>, not a copy kept in Vectispire: a
     *     licence can change between tags, and a copy would let somebody accept the wrong one
     */
    public record Contents(Map<String, Integer> languages, String licence, List<Entry> entries) {}

    /**
     * Refuses anything that is not a full commit SHA.
     *
     * <p>Forty hexadecimal characters, not an abbreviation: a short SHA is ambiguous by
     * construction, and an ambiguity in a provenance record is the one place it costs.
     */
    public static void requireCommit(String commit) {
        if (commit == null || !COMMIT.matcher(commit.trim().toLowerCase(Locale.ROOT)).matches()) {
            throw new IllegalArgumentException(
                    "A full 40-character commit SHA is required, not \"" + commit + "\".");
        }
    }

    public static void requireAllowed(String repository) {
        if (FORBIDDEN.contains(repository)) {
            throw new IllegalArgumentException(
                    repository + " is licensed under terms that forbid distributing its rules. "
                            + "Vectispire will not fetch it on anybody's behalf.");
        }
    }

    /** What the archive holds, grouped the way the operator will choose from it. */
    public static Contents describe(List<Entry> entries, String licence) {
        Map<String, Integer> byLanguage = new TreeMap<>();
        for (Entry entry : entries) {
            String language = topLevelOf(entry.path());
            if (language != null && isRule(entry)) {
                byLanguage.merge(language, 1, Integer::sum);
            }
        }
        return new Contents(byLanguage, licence, entries);
    }

    /**
     * The rule files for the chosen languages, as an upload.
     *
     * <p><b>The path is kept as the file's name, and that is not cosmetic.</b> Semgrep derives
     * a rule's {@code check_id} from its path unless {@code --no-rewrite-rule-ids} is passed,
     * and the rule id enters an issue's fingerprint. Losing the upstream path here would be
     * invisible today and would resolve every SAST finding the day it changed.
     */
    public static List<RuleSet.UploadedFile> select(Contents contents, Set<String> languages) {
        if (languages == null || languages.isEmpty()) {
            throw new IllegalArgumentException("Choose at least one language: a rule set with no rules resolves the backlog.");
        }
        Set<String> unknown = languages.stream()
                .filter(language -> !contents.languages().containsKey(language))
                .collect(java.util.stream.Collectors.toCollection(java.util.TreeSet::new));
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException("No such language in this tag: " + String.join(", ", unknown) + ".");
        }

        return contents.entries().stream()
                .filter(RuleCatalogue::isRule)
                // The null check before the lookup, not after: a root-level file has no
                // language, and `Set.of(…).contains(null)` throws rather than answering false.
                .filter(entry -> topLevelOf(entry.path()) != null)
                .filter(entry -> languages.contains(topLevelOf(entry.path())))
                .sorted(Comparator.comparing(Entry::path))
                .map(entry -> new RuleSet.UploadedFile(entry.path(), entry.content()))
                .toList();
    }

    /** Carries the short commit, so a set's origin is legible in a list a year later. */
    public static String nameFor(String commit, Set<String> languages) {
        return UPSTREAM + "@" + commit.substring(0, 12)
                + " (" + String.join(", ", new java.util.TreeSet<>(languages)) + ")";
    }

    private static boolean isRule(Entry entry) {
        return YAML.matcher(entry.path()).find()
                && !TEST_FIXTURE.matcher(entry.path()).find()
                && DECLARES_RULES.matcher(entry.content()).find()
                && DECLARES_A_RULE_ID.matcher(entry.content()).find();
    }

    private static String topLevelOf(String path) {
        int slash = path.indexOf('/');
        if (slash <= 0) {
            return null;
        }
        String first = path.substring(0, slash).toLowerCase(Locale.ROOT);
        return NOT_A_LANGUAGE.contains(first) ? null : first;
    }
}
