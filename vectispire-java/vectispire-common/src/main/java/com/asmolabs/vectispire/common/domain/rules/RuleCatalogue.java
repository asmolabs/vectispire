package com.asmolabs.vectispire.common.domain.rules;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.owasp.OwaspTag;
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

    /**
     * The upstream's ports of gitleaks' own rules, left out of an import unless asked for.
     *
     * <p><b>They duplicate the secrets step.</b> Vectispire's gitleaks configuration extends
     * gitleaks' defaults, so the 175 files under this directory — {@code generic-api-key},
     * {@code aws-access-token}, {@code private-key}… — look for what the secrets step already
     * looks for, with the same patterns. And the duplicate does not stay a duplicate: the finding
     * type enters an issue's fingerprint, so the same leaked key becomes a {@code secret} issue and
     * a {@code sast} twin. Triaging the secret — fixed, not affected — leaves the twin open, where it
     * can still fail the gate, add to the score and count its OWASP category a second time.
     *
     * <p>Excluded at the selection rather than reconciled later: merging findings across tools
     * would have the twin flap open and closed with every scan whose secrets step did not run
     * (decision 0007). An operator who runs without the secrets step, or wants both, opts in on
     * the import — one opt-in for these and for {@link #GITLEAKS_COVERED_SECURITY_RULES}, which
     * duplicate the step for the same reason.
     */
    public static final String GITLEAKS_PORTS = "generic/secrets/gitleaks/";

    /** Where {@link #GITLEAKS_COVERED_SECURITY_RULES} sit, beside the rules of that directory that stay. */
    public static final String SECURITY_SECRETS = "generic/secrets/security/";

    /**
     * The files of {@link #SECURITY_SECRETS} that a dedicated default rule of gitleaks already
     * covers — the same token format — left out with {@link #GITLEAKS_PORTS} and for the same
     * reason: each leak would come back as a {@code sast} twin of the {@code secret} issue, which
     * outlives the secret's triage.
     *
     * <p><b>Named one by one, against the gitleaks the secrets step runs</b> — v8.30.1, the image
     * {@code ScannerImages} pins — with the rule of its defaults that covers each, after the arrow.
     * The other files of the directory stay, because gitleaks' defaults have no rule for what they
     * look for: a bcrypt hash, an {@code /etc/shadow} line, a password in a URI, an AWS secret key
     * or session token, an {@code _authToken} in an {@code .npmrc}… <b>A gitleaks upgrade that
     * drops or narrows one of the rules named here means revisiting this list</b>: the entry would
     * then hide a leak nothing else looks for. A name absent from a given catalogue commit is simply not there — the list
     * selects, it does not require.
     *
     * <p>File stems, without {@code .yaml}: the rule's id is the same word, and a file renamed
     * upstream comes back in rather than vanishing, which is the safe way for this list to be wrong.
     */
    public static final List<String> GITLEAKS_COVERED_SECURITY_RULES = List.of(
            "detected-artifactory-token", //              → artifactory-api-key
            "detected-aws-access-key-id-value", //        → aws-access-token
            "detected-facebook-access-token", //          → facebook-page-access-token
            "detected-facebook-oauth", //                 → facebook-secret
            "detected-generic-api-key", //                → generic-api-key
            "detected-generic-secret", //                 → generic-api-key (its keywords include secret)
            "detected-github-token", //                   → github-pat, github-oauth, github-app-token, github-refresh-token
            "detected-google-api-key", //                 → gcp-api-key
            "detected-google-cloud-api-key", //           → gcp-api-key
            "detected-heroku-api-key", //                 → heroku-api-key
            "detected-jwt-token", //                      → jwt
            "detected-mailchimp-api-key", //              → mailchimp-api-key
            "detected-mailgun-api-key", //                → mailgun-private-api-token
            "detected-pgp-private-key-block", //          → private-key (BEGIN … PRIVATE KEY BLOCK)
            "detected-picatic-api-key", //                → stripe-access-token (the same sk_live_ format)
            "detected-private-key", //                    → private-key
            "detected-sendgrid-api-key", //               → sendgrid-api-token
            "detected-slack-token", //                    → slack-bot-token, slack-user-token, slack-legacy-*-token
            "detected-slack-webhook", //                  → slack-webhook-url
            "detected-snyk-api-key", //                   → snyk-api-token
            "detected-sonarqube-docs-api-key", //         → sonar-api-token
            "detected-square-access-token", //            → square-access-token
            "detected-stripe-api-key", //                 → stripe-access-token
            "detected-stripe-restricted-api-key", //      → stripe-access-token (rk_live_)
            "detected-telegram-bot-api-key", //           → telegram-bot-api-token
            "detected-twilio-api-key", //                 → twilio-api-key
            "google-maps-apikeyleak"); //                 → gcp-api-key

    /** {@link #GITLEAKS_COVERED_SECURITY_RULES} as the paths they sit at, in either YAML spelling. */
    private static final Set<String> GITLEAKS_COVERED_PATHS = GITLEAKS_COVERED_SECURITY_RULES.stream()
            .flatMap(stem -> java.util.stream.Stream.of(
                    SECURITY_SECRETS + stem + ".yaml", SECURITY_SECRETS + stem + ".yml"))
            .collect(java.util.stream.Collectors.toUnmodifiableSet());

    private RuleCatalogue() {}

    /** A file inside the fetched archive, already stripped of its top-level directory. */
    public record Entry(String path, String content) {}

    /**
     * @param languages how many rule files each top-level directory holds, ordered by name so
     *     two fetches of the same tag present the same list
     * @param categories how many rule files declare each OWASP category, read from their own
     *     {@code metadata.owasp}. <b>This is what makes "out of reach" checkable rather than
     *     asserted.</b> The grid marks a category uncovered when no installed rule declares it, so
     *     the question "can A09 be covered here" is not architectural but empirical: does this
     *     catalogue hold any. Nobody could answer without importing first, which is the reverse of
     *     the order an operator wants.
     * @param licence the text as it stands <b>at this tag</b>, not a copy kept in Vectispire: a
     *     licence can change between tags, and a copy would let somebody accept the wrong one
     * @param gitleaksDuplicates how many of the language counts' rule files duplicate the secrets
     *     step — under {@link #GITLEAKS_PORTS} or among {@link #GITLEAKS_COVERED_SECURITY_RULES} — and
     *     are left out of an import unless it asks for them: counted so the screen can say what the
     *     default leaves behind rather than import fewer files than it shows
     */
    public record Contents(
            Map<String, Integer> languages,
            Map<String, Integer> categories,
            String licence,
            List<Entry> entries,
            int gitleaksDuplicates) {}

    /**
     * Refuses anything that is not a full commit SHA.
     *
     * <p>Forty hexadecimal characters, not an abbreviation: a short SHA is ambiguous by
     * construction, and an ambiguity in a provenance record is the one place it costs.
     */
    public static void requireCommit(String commit) {
        if (commit == null || !COMMIT.matcher(commit.trim().toLowerCase(Locale.ROOT)).matches()) {
            throw new InvalidInputException(
                    "A full 40-character commit SHA is required, not \"" + commit + "\".");
        }
    }

    public static void requireAllowed(String repository) {
        if (FORBIDDEN.contains(repository)) {
            throw new InvalidInputException(
                    repository + " is licensed under terms that forbid distributing its rules. "
                            + "Vectispire will not fetch it on anybody's behalf.");
        }
    }

    /** What the archive holds, grouped the way the operator will choose from it. */
    public static Contents describe(List<Entry> entries, String licence) {
        Map<String, Integer> byLanguage = new TreeMap<>();
        Map<String, Integer> byCategory = new TreeMap<>();
        int gitleaksDuplicates = 0;
        for (Entry entry : entries) {
            if (!isRule(entry)) {
                continue;
            }
            if (isGitleaksDuplicate(entry)) {
                gitleaksDuplicates++;
            }
            String language = topLevelOf(entry.path());
            if (language != null) {
                byLanguage.merge(language, 1, Integer::sum);
            }
            // A rule may declare several; each counts for what it covers.
            for (String category : OwaspTag.declaredIn(entry.content())) {
                byCategory.merge(category, 1, Integer::sum);
            }
        }
        return new Contents(byLanguage, byCategory, licence, entries, gitleaksDuplicates);
    }

    /**
     * The rule files for the chosen languages, as an upload.
     *
     * <p><b>The path is kept as the file's name, and that is not cosmetic.</b> Semgrep derives
     * a rule's {@code check_id} from its path unless {@code --no-rewrite-rule-ids} is passed,
     * and the rule id enters an issue's fingerprint. Losing the upstream path here would be
     * invisible today and would resolve every SAST finding the day it changed.
     *
     * <p>Without {@link #GITLEAKS_PORTS} and {@link #GITLEAKS_COVERED_SECURITY_RULES}, which only
     * {@link #select(Contents, Set, boolean)} brings in.
     */
    public static List<RuleSet.UploadedFile> select(Contents contents, Set<String> languages) {
        return select(contents, languages, false);
    }

    /**
     * The rule files for the chosen languages, with or without the rules that duplicate gitleaks.
     *
     * @param includeGitleaksDuplicates the operator's opt-in to {@link #GITLEAKS_PORTS} and {@link
     *     #GITLEAKS_COVERED_SECURITY_RULES}: for an installation whose scans run no secrets step,
     *     where they are not a duplicate
     */
    public static List<RuleSet.UploadedFile> select(
            Contents contents, Set<String> languages, boolean includeGitleaksDuplicates) {
        if (languages == null || languages.isEmpty()) {
            throw new InvalidInputException("Choose at least one language: a rule set with no rules resolves the backlog.");
        }
        Set<String> unknown = languages.stream()
                .filter(language -> !contents.languages().containsKey(language))
                .collect(java.util.stream.Collectors.toCollection(java.util.TreeSet::new));
        if (!unknown.isEmpty()) {
            throw new InvalidInputException("No such language in this tag: " + String.join(", ", unknown) + ".");
        }

        List<RuleSet.UploadedFile> selected = contents.entries().stream()
                .filter(RuleCatalogue::isRule)
                // The null check before the lookup, not after: a root-level file has no
                // language, and `Set.of(…).contains(null)` throws rather than answering false.
                .filter(entry -> topLevelOf(entry.path()) != null)
                .filter(entry -> languages.contains(topLevelOf(entry.path())))
                .filter(entry -> includeGitleaksDuplicates || !isGitleaksDuplicate(entry))
                .sorted(Comparator.comparing(Entry::path))
                .map(entry -> new RuleSet.UploadedFile(entry.path(), entry.content()))
                .toList();
        // Said here, in these words: a language holding nothing but those rules would otherwise
        // reach the store as "No file was uploaded", which names the wrong gesture.
        if (selected.isEmpty()) {
            throw new InvalidInputException("These languages hold only rules that duplicate gitleaks, which the "
                    + "secrets step already runs. Choose another language, or include the gitleaks duplicates.");
        }
        return selected;
    }

    /** Whether the chosen languages hold any rule that duplicates gitleaks — what the default left out. */
    public static boolean reachesGitleaksDuplicates(Contents contents, Set<String> languages) {
        return contents.entries().stream()
                .filter(RuleCatalogue::isRule)
                .filter(RuleCatalogue::isGitleaksDuplicate)
                .anyMatch(entry -> languages.contains(topLevelOf(entry.path())));
    }

    /** Carries the short commit, so a set's origin is legible in a list a year later. */
    public static String nameFor(String commit, Set<String> languages) {
        return UPSTREAM + "@" + commit.substring(0, 12)
                + " (" + String.join(", ", new java.util.TreeSet<>(languages)) + ")";
    }

    /**
     * As {@link #nameFor(String, Set)}, marked when the set holds the rules that duplicate gitleaks — the
     * exception to the default, which is what a reader of the list needs to see.
     */
    public static String nameFor(String commit, Set<String> languages, boolean holdsGitleaksDuplicates) {
        return nameFor(commit, languages) + (holdsGitleaksDuplicates ? " with gitleaks duplicates" : "");
    }

    private static boolean isRule(Entry entry) {
        return YAML.matcher(entry.path()).find()
                && !TEST_FIXTURE.matcher(entry.path()).find()
                && DECLARES_RULES.matcher(entry.content()).find()
                && DECLARES_A_RULE_ID.matcher(entry.content()).find();
    }

    /** Compared in lower case like the language, so a capitalised directory is not a way past it. */
    private static boolean isGitleaksDuplicate(Entry entry) {
        String path = entry.path().toLowerCase(Locale.ROOT);
        return path.startsWith(GITLEAKS_PORTS) || GITLEAKS_COVERED_PATHS.contains(path);
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
