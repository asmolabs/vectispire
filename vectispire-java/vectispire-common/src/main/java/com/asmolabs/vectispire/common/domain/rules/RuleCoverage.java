package com.asmolabs.vectispire.common.domain.rules;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Whether this instance's static analysis covers the code it is pointed at.
 *
 * <h2>The failure this describes</h2>
 *
 * <p><b>Vectispire ships one Semgrep rule.</b> The jar carries a Gitleaks configuration and a
 * single pattern — dangerous evaluation, in Python. Everything else is an operator's act: import
 * the upstream catalogue, point at a directory, or upload a rule set. And the scan container has
 * no network, deliberately, so nothing can be fetched at scan time; whatever is going to be used
 * has to be on disk first.
 *
 * <p>Which means a fresh deployment analyses one pattern in one language and reports no findings
 * — a result indistinguishable, on every screen, from code that is clean. Nothing says so today.
 *
 * <h2>Three states, and why not two</h2>
 *
 * <p>{@link State#UNCONFIGURED} is the factory default and the one worth saying loudest.
 * {@link State#PARTIAL} is an instance with rules that do not reach some language it is actually
 * scanning. {@link State#COVERED} raises nothing at all — a warning shown when everything is fine
 * loses its meaning within days, and then the one that matters is invisible too.
 *
 * <h2>What the estate's languages are inferred from, and its limits</h2>
 *
 * <p>Package URLs, which name an ecosystem rather than a language: {@code pkg:maven} means the
 * repository builds with Maven, from which Java is a fair guess and Kotlin or Scala are equally
 * possible. <b>The inference is deliberately coarse</b>, and it is the honest shape of what the
 * inventory knows — a precise answer would need a language census this product does not take. It
 * is enough for the question being asked, which is whether an ecosystem is covered at all.
 */
public final class RuleCoverage {

    private RuleCoverage() {}

    public enum State {
        /** Only what the jar ships: one pattern, one language. */
        UNCONFIGURED,
        /** Rules are present, and at least one ecosystem in the estate has none. */
        PARTIAL,
        /** Every ecosystem seen in the estate has rules. */
        COVERED
    }

    /**
     * @param languagesWithRules the rule directories present, lowercased
     * @param ecosystemsInEstate what the components say the estate is written in
     * @param uncovered ecosystems present with no rules. Empty when {@code state} is not PARTIAL
     * @param ruleFiles how many rule files are installed, bundled included
     */
    public record Assessment(
            State state,
            Set<String> languagesWithRules,
            Set<String> ecosystemsInEstate,
            Set<String> uncovered,
            int ruleFiles) {}

    /**
     * The one rule the jar ships, by the directory it lands in.
     *
     * <p>An instance holding only this is unconfigured however many files that is — the count is
     * not the question, reaching the code is.
     */
    public static final String BUNDLED_LANGUAGE = "python";

    /**
     * Package ecosystems mapped to the rule directory that would cover them.
     *
     * <p>Insertion-ordered so the reader of a diff sees a list rather than a reshuffle. An
     * ecosystem absent from this map is not reported as uncovered: saying "no rules for cargo"
     * when nobody has written the mapping would be blaming the estate for a gap in this table.
     */
    private static final Map<String, String> ECOSYSTEM_LANGUAGE = ecosystems();

    private static Map<String, String> ecosystems() {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("maven", "java");
        map.put("gradle", "java");
        map.put("npm", "javascript");
        map.put("pypi", "python");
        map.put("golang", "go");
        map.put("go", "go");
        map.put("cargo", "rust");
        map.put("nuget", "csharp");
        map.put("composer", "php");
        map.put("gem", "ruby");
        return Map.copyOf(map);
    }

    /**
     * @param ruleFilePaths every installed rule file, path relative to the rules directory
     * @param purls the package URLs the inventory holds
     */
    public static Assessment assess(List<String> ruleFilePaths, List<String> purls) {
        Set<String> languages = new TreeSet<>();
        for (String path : ruleFilePaths) {
            languageOf(path).ifPresent(languages::add);
        }

        Set<String> ecosystems = new TreeSet<>();
        for (String purl : purls) {
            ecosystemOf(purl).ifPresent(ecosystems::add);
        }

        Set<String> uncovered = new TreeSet<>();
        for (String ecosystem : ecosystems) {
            String language = ECOSYSTEM_LANGUAGE.get(ecosystem);
            if (language != null && !languages.contains(language)) {
                uncovered.add(ecosystem);
            }
        }

        // Only the shipped rule: unconfigured, whatever the estate turns out to contain. Said
        // before the per-ecosystem comparison because it is a different sentence — "nothing is
        // configured" rather than "something is missing".
        boolean onlyBundled = languages.isEmpty() || languages.equals(Set.of(BUNDLED_LANGUAGE));
        State state = onlyBundled
                ? State.UNCONFIGURED
                : uncovered.isEmpty() ? State.COVERED : State.PARTIAL;

        return new Assessment(
                state,
                Set.copyOf(languages),
                Set.copyOf(ecosystems),
                state == State.PARTIAL ? Set.copyOf(uncovered) : Set.of(),
                ruleFilePaths.size());
    }

    /**
     * {@code semgrep/java/xss.yaml} → {@code java}.
     *
     * <p><b>Semgrep's tree only.</b> Gitleaks ships one configuration file rather than a directory
     * per language, so counting its path as a language made {@code gitleaks} a language and an
     * unconfigured instance look configured — which is exactly the reading this class exists to
     * prevent, produced by this class.
     */
    private static Optional<String> languageOf(String path) {
        if (path == null) {
            return Optional.empty();
        }
        List<String> segments = new ArrayList<>(List.of(path.replace('\\', '/').split("/")));
        segments.removeIf(String::isBlank);
        if (segments.size() < 3 || !"semgrep".equalsIgnoreCase(segments.getFirst())) {
            return Optional.empty();
        }
        return Optional.of(segments.get(1).toLowerCase(Locale.ROOT));
    }

    /** {@code pkg:maven/org.acme/thing@1.2} → {@code maven}. */
    private static Optional<String> ecosystemOf(String purl) {
        if (purl == null || !purl.startsWith("pkg:")) {
            return Optional.empty();
        }
        String rest = purl.substring("pkg:".length());
        int slash = rest.indexOf('/');
        if (slash <= 0) {
            return Optional.empty();
        }
        return Optional.of(rest.substring(0, slash).toLowerCase(Locale.ROOT));
    }
}
