package com.asmolabs.vectispire.common.domain.dependencies;

import java.util.Collection;
import java.util.Comparator;
import java.util.Optional;

/**
 * Comparing two versions the way a human reads them, and not the way a string sort orders them.
 *
 * <p><b>What this class makes possible.</b> The remediation screen says which version to install.
 * The answer is in the findings — each carries the versions that fix the vulnerability it describes
 * — but there are several per package, and choosing the right one means comparing them.
 * Lexicographically {@code "2.9.0"} comes after {@code "2.17.1"}, and the screen would advise
 * installing a version that leaves the hole open.
 *
 * <p><b>This is not a semver implementation.</b> The versions here come from six ecosystems and
 * reliably respect none of them. What is done: split on dots, hyphens and underscores, compare
 * numerically what is numeric and alphabetically the rest, and treat absent segments as zeros so
 * that {@code 2.17} and {@code 2.17.0} are equal. What is not done: semver's pre-release
 * precedence — {@code 1.0.0-alpha} sorts here <em>after</em> {@code 1.0.0} and not before. That is
 * a choice: advising a version one notch too high is harmless, advising one too low leaves the
 * hole.
 */
public final class Versions {

    /** The separators of the six ecosystems tracked, taken together. */
    private static final String SEPARATORS = "[._\\-+]";

    public static final Comparator<String> ASCENDING = Versions::compare;

    /**
     * The highest of a set, ignoring what is not a version.
     *
     * <p>Empty rather than a placeholder text: "no fixed version published" and "upgrade to this
     * one" are two different answers, and the screen must be able to say them differently. The
     * field used to carry the string {@code "latest-patch"}, printed as it stood behind an arrow on
     * the dashboard — neither a version nor an admission of ignorance.
     */
    public static Optional<String> highest(Collection<String> candidates) {
        if (candidates == null) {
            return Optional.empty();
        }
        return candidates.stream()
                .filter(candidate -> candidate != null && !candidate.isBlank())
                .map(String::trim)
                .max(ASCENDING);
    }

    /**
     * The versions of a comma-separated list, as the scanners report it.
     *
     * <p>{@code fix_versions} is not a version but an enumeration: "2.12.2, 2.3.2, 2.17.1" when a
     * maintenance branch was fixed at the same time as the main one.
     */
    public static java.util.List<String> split(String commaSeparated) {
        if (commaSeparated == null || commaSeparated.isBlank()) {
            return java.util.List.of();
        }
        return java.util.Arrays.stream(commaSeparated.split(","))
                .map(String::trim)
                .filter(part -> !part.isEmpty())
                .toList();
    }

    public static int compare(String left, String right) {
        String[] leftParts = left.split(SEPARATORS);
        String[] rightParts = right.split(SEPARATORS);

        int length = Math.max(leftParts.length, rightParts.length);
        for (int index = 0; index < length; index++) {
            // An absent segment counts as zero, without which 2.17 and 2.17.0 would differ by
            // their spelling and not by what they designate.
            String leftPart = index < leftParts.length ? leftParts[index] : "0";
            String rightPart = index < rightParts.length ? rightParts[index] : "0";

            int verdict = comparePart(leftPart, rightPart);
            if (verdict != 0) {
                return verdict;
            }
        }
        return 0;
    }

    private static int comparePart(String left, String right) {
        boolean leftIsNumber = isNumber(left);
        boolean rightIsNumber = isNumber(right);

        if (leftIsNumber && rightIsNumber) {
            // Compared as a long and not as a string: "10" comes after "9". Segments too long for
            // a long do exist (packed dates, build identifiers) and then fall back on the textual
            // comparison rather than throwing.
            try {
                return Long.compare(Long.parseLong(left), Long.parseLong(right));
            } catch (NumberFormatException overflow) {
                return left.length() != right.length()
                        ? Integer.compare(left.length(), right.length())
                        : left.compareTo(right);
            }
        }
        if (leftIsNumber != rightIsNumber) {
            // A digit beats a word: `2.0` comes after `2.rc`, and a textual suffix almost always
            // means a pre-release in the ecosystems tracked.
            return leftIsNumber ? 1 : -1;
        }
        return left.compareToIgnoreCase(right);
    }

    private static boolean isNumber(String part) {
        if (part.isEmpty()) {
            return false;
        }
        for (int index = 0; index < part.length(); index++) {
            if (!Character.isDigit(part.charAt(index))) {
                return false;
            }
        }
        return true;
    }

    private Versions() {}
}
