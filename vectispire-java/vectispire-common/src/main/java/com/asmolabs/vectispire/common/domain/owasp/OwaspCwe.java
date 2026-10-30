package com.asmolabs.vectispire.common.domain.owasp;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The OWASP Top 10 2021 category a CWE belongs to, by the standard's own lists.
 *
 * <h2>Why this is not the guess {@link OwaspCoverage} refuses</h2>
 *
 * <p>The grid places findings by rule, never by matching words in a rule identifier. A CWE is not
 * such a word: it is the weakness the rule's author declared in {@code metadata.cwe}, and OWASP
 * publishes, for each 2021 category, the list of CWEs it maps to it ("List of Mapped CWEs"). Reading
 * the author's CWE and looking it up in OWASP's list is two declarations put end to end — each one a
 * sentence an assessor can check — and it is used only where the rule declared no 2021 category of
 * its own ({@link OwaspTag}), which stays the first word.
 *
 * <p><b>Without it, an untagged code finding entered no category at all, silently</b>: most of the
 * upstream corpus declares a CWE and no OWASP category, so an injection found by such a rule was
 * counted nowhere in the grid while the category read "nothing found".
 *
 * <h2>Where the table comes from</h2>
 *
 * <p>The ten "List of Mapped CWEs" of the OWASP Top 10 2021, at commit {@code 3a31f353} of
 * {@code github.com/OWASP/Top10} ({@code 2021/docs/en/A0n_2021-*.md}). Each list's length is the
 * "CWEs Mapped" figure its page states, which {@code OwaspCweTest} checks.
 *
 * <p><b>One CWE appears in two lists</b>: CWE-259, use of hard-coded password, under A02 and A07.
 * A02's page counts 29 CWEs and lists 30, A07's counts 22 and lists 22 with it — so it is A07's, which
 * is also where {@link OwaspCoverage} files a hard-coded secret (CWE-798). A finding counted in two
 * categories would inflate the only number the grid carries.
 */
public final class OwaspCwe {

    private OwaspCwe() {}

    /** CWE number → 2021 category, every CWE once. */
    private static final Map<Integer, String> CATEGORY_BY_CWE = table();

    private static final Pattern CWE = Pattern.compile("\\bCWE-(\\d+)\\b", Pattern.CASE_INSENSITIVE);

    private static Map<Integer, String> table() {
        Map<Integer, String> table = new TreeMap<>();
        put(table, "A01", 22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497,
                538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275);
        // Without CWE-259, which the page lists and does not count: A07 counts it (see above).
        put(table, "A02", 261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338,
                340, 347, 523, 720, 757, 759, 760, 780, 818, 916);
        put(table, "A03", 20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116,
                138, 184, 470, 471, 564, 610, 643, 644, 652, 917);
        put(table, "A04", 73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451,
                472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927,
                1021, 1173);
        put(table, "A05", 2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004,
                1032, 1174);
        put(table, "A06", 937, 1035, 1104);
        put(table, "A07", 255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640,
                798, 940, 1216);
        put(table, "A08", 345, 353, 426, 494, 502, 565, 784, 829, 830, 915);
        put(table, "A09", 117, 223, 532, 778);
        put(table, "A10", 918);
        return Collections.unmodifiableMap(table);
    }

    private static void put(Map<Integer, String> table, String category, int... cwes) {
        for (int cwe : cwes) {
            String previous = table.putIfAbsent(cwe, category);
            if (previous != null) {
                throw new IllegalStateException("CWE-" + cwe + " is mapped to " + previous + " and " + category
                        + ": a finding would be counted in two categories.");
            }
        }
    }

    /** The 2021 category of one CWE number, or nothing for a CWE no list names. */
    public static Optional<String> categoryOf(int cwe) {
        return Optional.ofNullable(CATEGORY_BY_CWE.get(cwe));
    }

    /**
     * The category of the first CWE in a declaration that maps to one — {@code "CWE-89: Improper
     * Neutralization…"}, the form the upstream rules write.
     *
     * <p>The first, as {@link OwaspTag#categoryOf} takes the first category: one finding, one category.
     */
    public static Optional<String> categoryOfDeclaration(String declaration) {
        Matcher matcher = CWE.matcher(declaration == null ? "" : declaration);
        while (matcher.find()) {
            Optional<String> category = number(matcher.group(1)).flatMap(OwaspCwe::categoryOf);
            if (category.isPresent()) {
                return category;
            }
        }
        return Optional.empty();
    }

    /** Every category the CWEs of a text map to, in the order they appear. */
    static Set<String> categoriesIn(String text) {
        Set<String> found = new LinkedHashSet<>();
        Matcher matcher = CWE.matcher(text == null ? "" : text);
        while (matcher.find()) {
            number(matcher.group(1)).flatMap(OwaspCwe::categoryOf).ifPresent(found::add);
        }
        return found;
    }

    /** How many CWEs the table maps to one category. */
    static long mappedTo(String category) {
        return CATEGORY_BY_CWE.values().stream().filter(category::equals).count();
    }

    private static Optional<Integer> number(String digits) {
        try {
            return Optional.of(Integer.parseInt(digits));
        } catch (NumberFormatException tooLong) {
            return Optional.empty();
        }
    }
}
