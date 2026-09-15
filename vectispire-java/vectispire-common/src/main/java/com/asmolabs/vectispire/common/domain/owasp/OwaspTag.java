package com.asmolabs.vectispire.common.domain.owasp;

import java.util.LinkedHashSet;
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

    /** The key, wherever it sits in the indentation. */
    private static final Pattern OWASP_KEY = Pattern.compile("(?m)^(\\s*)-?\\s*owasp\\s*:(.*)$");

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
        if (yaml == null || yaml.isBlank()) {
            return found;
        }

        Matcher key = OWASP_KEY.matcher(yaml);
        while (key.find()) {
            // The inline form — `owasp: A03:2021 - Injection` — and the block form that follows
            // it are both ordinary here: the first is what is left on the key's own line, the
            // second is everything indented under it.
            collect(key.group(2), found);
            collect(block(yaml, key.end(), key.group(1).length()), found);
        }
        return found;
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
