package com.asmolabs.vectispire.common.domain.owasp;

import java.util.Collection;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The OWASP category a Semgrep rule declares about itself, read from its own words.
 *
 * <h2>Why this reads metadata and refuses everything else</h2>
 *
 * <p>{@link OwaspCoverage} places findings in the Top 10 <b>by rule, never by guess</b>, and said
 * so about code analysis in particular: a mapping built from substrings in a rule identifier
 * would be reproducible and still a guess dressed as a rule. This is the other way round — the
 * rule's author declared the category in the rule's own {@code metadata.owasp}, and reading a
 * declaration is not guessing. Where there is no declaration, nothing is placed.
 *
 * <h2>The trap: two editions share the same letters</h2>
 *
 * <p><b>{@code A01:2017} is Injection. {@code A01:2021} is Broken Access Control.</b> The
 * upstream rules carry both editions side by side, often on the same rule:
 *
 * <pre>{@code
 * owasp:
 *   - A01:2017 - Injection
 *   - A03:2021 - Injection
 * }</pre>
 *
 * <p>A pattern reading {@code A\d\d} would therefore file injection findings under Broken Access
 * Control — a wrong answer that looks like a right one, in the one document an assessor reads
 * category by category. Only the 2021 edition is accepted here, because that is the edition
 * {@link OwaspCoverage#CATEGORIES} describes and the one every questionnaire still asks about. A
 * rule declaring only the 2017 edition places nothing, which is the conservative half of the same
 * decision.
 *
 * <h2>Another edition is refused, never forgotten</h2>
 *
 * <p>The 2025 edition reshuffles the letters again, and decision 0046 keeps 2021 for 1.0 — so a rule
 * tagged {@code A01:2025} alone places nothing either. <b>It used to place nothing in silence</b>: the
 * rule ran, its findings reached the backlog with no category, and the grid read the category it was
 * written for as uncovered with no word of why. {@link #untaggedReasonOf} names that case, and {@link
 * #tally} counts it among the untagged rules with its reason, so the rule set's coverage says how many
 * rules were written against an edition this product does not place — unless a CWE it declares places
 * it, by the standard's own lists ({@link #placedIn}, {@link OwaspCwe}).
 *
 * <h2>Why a scan of the metadata block and not a YAML parse</h2>
 *
 * <p>The tokens are searched for <b>inside an {@code owasp:} block only</b>, and not anywhere in
 * the file. A rule whose message mentions {@code A03:2021} in prose would otherwise be counted as
 * declaring the category, and the coverage grid would claim a category the installed rules cannot
 * actually produce — exactly the false green the grid exists to remove.
 *
 * <p>No YAML parser, for the reason {@code RuleCatalogue} gives about the same files: the rule
 * corpus is somebody else's, it is large, and a parser that refuses one malformed file would take
 * the whole set with it. A scan degrades to "declares nothing", which is the safe direction.
 */
public final class OwaspTag {

    private OwaspTag() {}

    /**
     * The 2021 edition's own spelling, and nothing else.
     *
     * <p>The year is part of the pattern rather than optional: it is the only thing separating
     * the two editions, and it is what makes this a reading rather than an interpretation.
     */
    private static final Pattern CATEGORY_2021 = Pattern.compile("\\b(A0[1-9]|A10):2021\\b");

    /**
     * The 2025 edition's spelling — read only to say that a rule was refused, never to place it.
     *
     * <p>Not mapped onto 2021: the editions share their letters and not their meanings, which is the
     * trap above in another year.
     */
    private static final Pattern CATEGORY_2025 = Pattern.compile("\\bA(0[1-9]|10):2025\\b");

    /** The 2017 edition, which upstream also spells without the zero ({@code A1:2017}). */
    private static final Pattern CATEGORY_2017 = Pattern.compile("\\bA(0?[1-9]|10):2017\\b");

    /** The key, wherever it sits in the indentation. */
    private static final Pattern OWASP_KEY = Pattern.compile("(?m)^(\\s*)-?\\s*owasp\\s*:(.*)$");

    /** The weakness the rule declares — {@link OwaspCwe} places a rule declaring no 2021 category by it. */
    private static final Pattern CWE_KEY = Pattern.compile("(?m)^(\\s*)-?\\s*cwe\\s*:(.*)$");

    /**
     * The categories one rule file declares.
     *
     * @param yaml the rule file's content; a null or blank file declares nothing
     * @return the ids, in the order the file names them — an ordered set so two readings of one
     *     corpus produce the same list, which is what makes the coverage grid comparable to
     *     yesterday's
     */
    public static Set<String> declaredIn(String yaml) {
        Set<String> found = new LinkedHashSet<>();
        collect(declarations(yaml, OWASP_KEY), found);
        return found;
    }

    /**
     * The categories one rule file places its findings in: those it declares, or — when it declares no
     * 2021 category — those its CWEs map to in the standard's own lists ({@link OwaspCwe}).
     *
     * <p><b>The same order of precedence as a finding's</b> ({@code SastScanner}): the grid counts a
     * category covered when a rule places findings there, and a rule credited with a category its
     * findings cannot reach — or denied one they do reach — is a grid saying the opposite of the backlog.
     * A file holding several rules is read as a whole, as {@link #declaredIn} reads it: a file whose
     * rules declare no 2021 category is placed by every CWE they name.
     */
    public static Set<String> placedIn(String yaml) {
        Set<String> declared = declaredIn(yaml);
        return declared.isEmpty() ? OwaspCwe.categoriesIn(declarations(yaml, CWE_KEY)) : declared;
    }

    /**
     * Why a rule file places nothing in the grid — the reason it is counted untagged.
     *
     * <p>A file declaring a 2021 category is tagged, whatever else it declares. One declaring the 2025
     * edition alone is named before one declaring the 2017 edition alone: a file carrying both was
     * written against the newer, and that is the edition an author would be asked to add 2021 beside.
     *
     * @return empty for a file that declares a 2021 category
     */
    public static Optional<Untagged> untaggedReasonOf(String yaml) {
        String declared = declarations(yaml, OWASP_KEY);
        if (CATEGORY_2021.matcher(declared).find()) {
            return Optional.empty();
        }
        if (CATEGORY_2025.matcher(declared).find()) {
            return Optional.of(Untagged.ONLY_2025_EDITION);
        }
        if (CATEGORY_2017.matcher(declared).find()) {
            return Optional.of(Untagged.ONLY_2017_EDITION);
        }
        return Optional.of(Untagged.NOT_DECLARED);
    }

    /** Why a rule file declares no 2021 category, in the order {@link OwaspTagging#untagged} lists them. */
    public enum Untagged {
        /** Its {@code metadata.owasp} names the 2025 edition and not 2021 (decision 0046). */
        ONLY_2025_EDITION,
        /** Its {@code metadata.owasp} names the 2017 edition and not 2021. */
        ONLY_2017_EDITION,
        /** It has no {@code metadata.owasp} at all, or none this reading recognises. */
        NOT_DECLARED
    }

    /** How many rule files are untagged for one reason. */
    public record OwaspUntaggedCount(Untagged reason, int ruleFiles) {}

    /**
     * How the installed rule files declare their OWASP category.
     *
     * @param ruleFiles the rule files read — the code-analysis rules only, not the secrets configuration
     * @param tagged those declaring at least one 2021 category
     * @param byCwe those declaring none, placed by a CWE they declare ({@link #placedIn}): untagged, and
     *     placed all the same
     * @param untagged the rest — the rules the grid can place no finding of — one count per reason in
     *     {@link Untagged}'s order, a reason with no file left out; their counts sum to {@code ruleFiles -
     *     tagged - byCwe}
     */
    public record OwaspTagging(int ruleFiles, int tagged, int byCwe, List<OwaspUntaggedCount> untagged) {

        public OwaspTagging {
            untagged = List.copyOf(untagged);
        }
    }

    /** {@link OwaspTagging} over the contents of the rule files. */
    public static OwaspTagging tally(Collection<String> ruleFiles) {
        Map<Untagged, Integer> untagged = new EnumMap<>(Untagged.class);
        int tagged = 0;
        int byCwe = 0;
        for (String content : ruleFiles) {
            Optional<Untagged> reason = untaggedReasonOf(content);
            if (reason.isEmpty()) {
                tagged++;
            } else if (!placedIn(content).isEmpty()) {
                byCwe++;
            } else {
                untagged.merge(reason.get(), 1, Integer::sum);
            }
        }
        return new OwaspTagging(ruleFiles.size(), tagged, byCwe, untagged.entrySet().stream()
                .map(entry -> new OwaspUntaggedCount(entry.getKey(), entry.getValue()))
                .toList());
    }

    /**
     * Everything the file's keys of this name hold, inline and indented under them — the only text a
     * declaration is read from.
     */
    private static String declarations(String yaml, Pattern keyPattern) {
        StringBuilder declared = new StringBuilder();
        if (yaml == null || yaml.isBlank()) {
            return "";
        }
        Matcher key = keyPattern.matcher(yaml);
        while (key.find()) {
            // The inline form — `owasp: A03:2021 - Injection` — and the block form that follows
            // it are both ordinary here: the first is what is left on the key's own line, the
            // second is everything indented under it.
            declared.append(key.group(2)).append('\n');
            declared.append(block(yaml, key.end(), key.group(1).length()));
        }
        return declared.toString();
    }

    /** The single category of a scanner's finding, when it declared exactly one usable value. */
    public static Optional<String> categoryOf(String declaration) {
        Matcher matcher = CATEGORY_2021.matcher(declaration == null ? "" : declaration);
        return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
    }

    private static void collect(String text, Set<String> into) {
        Matcher matcher = CATEGORY_2021.matcher(text);
        while (matcher.find()) {
            into.add(matcher.group(1));
        }
    }

    /**
     * What is indented under the key, up to the next line that is not.
     *
     * <p>The end of the block is a line at the same indentation or less — the only structure YAML
     * offers without parsing it. A blank line inside a block does not end it, which is how a
     * human writes one.
     */
    private static String block(String yaml, int from, int indent) {
        StringBuilder inside = new StringBuilder();
        for (String line : yaml.substring(from).split("\n")) {
            if (line.isBlank()) {
                continue;
            }
            int leading = line.length() - line.stripLeading().length();
            if (leading <= indent) {
                break;
            }
            inside.append(line).append('\n');
        }
        return inside.toString();
    }
}
