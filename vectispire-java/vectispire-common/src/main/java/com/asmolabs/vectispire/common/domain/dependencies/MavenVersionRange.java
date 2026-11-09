package com.asmolabs.vectispire.common.domain.dependencies;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A Maven version range — {@code [1.17,2.0)}, {@code [1.17.7]}, {@code (,2.0)}, {@code [1.0,1.2],[1.5,)}
 * — and whether a version is in it, by {@link MavenVersion}'s order.
 *
 * <p>The syntax is Maven's own: a square bracket includes its bound, a parenthesis excludes it, an
 * empty side is unbounded, a lone version in square brackets is that version, and a comma between
 * ranges is their union. What Maven refuses is refused here too, in words — a bound that is not a
 * version, a lone version in parentheses, a lower bound above the upper one, ranges that overlap — and
 * so is what Maven reads without complaint and nobody means: a range that admits no version ({@code
 * (1.0,1.0)}), and an unbounded side written with a square bracket ({@code [,2.0)}), since a bracket
 * promises a bound it does not name. A bare version is not a range: Maven reads {@code 1.0} as "1.0,
 * or anything", and a checklist that allows anything must not look as if it allowed one version.
 */
public final class MavenVersionRange {

    private final String written;
    private final List<Restriction> restrictions;

    private MavenVersionRange(String written, List<Restriction> restrictions) {
        this.written = written;
        this.restrictions = List.copyOf(restrictions);
    }

    /** Whether the text is written as a range — it opens with a bracket or a parenthesis. */
    public static boolean looksLikeRange(String spec) {
        String text = spec == null ? "" : spec.strip();
        return text.startsWith("[") || text.startsWith("(");
    }

    /** The range, or a refusal saying what is wrong with it. */
    public static MavenVersionRange parse(String spec) {
        String text = spec == null ? "" : spec.strip();
        if (!looksLikeRange(text)) {
            throw refused(text, "a range opens with [ or (");
        }
        List<Restriction> restrictions = new ArrayList<>();
        String rest = text;
        while (rest.startsWith("[") || rest.startsWith("(")) {
            int close = firstClose(rest);
            if (close < 0) {
                throw refused(text, "a range closes with ] or )");
            }
            Restriction restriction = restriction(text, rest.substring(0, close + 1));
            if (!restrictions.isEmpty()) {
                Restriction previous = restrictions.getLast();
                if (previous.upper().isEmpty() || restriction.lower().isEmpty()) {
                    throw refused(text, "its ranges overlap — an unbounded side can only be the first range's lower"
                            + " or the last one's upper");
                }
                int order = previous.upper().get().compareTo(restriction.lower().get());
                if (order > 0 || order == 0 && previous.upperInclusive() && restriction.lowerInclusive()) {
                    throw refused(text, "its ranges overlap or are out of order — write them from the lowest up");
                }
            }
            restrictions.add(restriction);
            rest = rest.substring(close + 1).strip();
            if (rest.startsWith(",")) {
                rest = rest.substring(1).strip();
                if (rest.isEmpty()) {
                    throw refused(text, "a comma between ranges is followed by another range");
                }
            }
        }
        if (!rest.isEmpty()) {
            throw refused(text, "\"" + BoundedText.clip(rest, 40) + "\" follows the ranges — a version allowed on its own"
                    + " is a separate entry of the list");
        }
        return new MavenVersionRange(text, restrictions);
    }

    /** The range when the text is one, and absent otherwise — never a refusal: for text stored before. */
    public static Optional<MavenVersionRange> read(String spec) {
        if (!looksLikeRange(spec)) {
            return Optional.empty();
        }
        try {
            return Optional.of(parse(spec));
        } catch (InvalidInputException unreadable) {
            return Optional.empty();
        }
    }

    public boolean contains(String version) {
        MavenVersion candidate = MavenVersion.of(version);
        return restrictions.stream().anyMatch(restriction -> restriction.contains(candidate));
    }

    @Override
    public String toString() {
        return written;
    }

    private record Restriction(Optional<MavenVersion> lower, boolean lowerInclusive, Optional<MavenVersion> upper,
            boolean upperInclusive) {

        boolean contains(MavenVersion version) {
            if (lower.isPresent()) {
                int order = version.compareTo(lower.get());
                if (order < 0 || order == 0 && !lowerInclusive) {
                    return false;
                }
            }
            if (upper.isPresent()) {
                int order = version.compareTo(upper.get());
                return order < 0 || order == 0 && upperInclusive;
            }
            return true;
        }
    }

    private static int firstClose(String text) {
        int square = text.indexOf(']');
        int round = text.indexOf(')');
        if (square < 0) {
            return round;
        }
        return round < 0 ? square : Math.min(square, round);
    }

    private static Restriction restriction(String whole, String spec) {
        boolean lowerInclusive = spec.startsWith("[");
        boolean upperInclusive = spec.endsWith("]");
        String inner = spec.substring(1, spec.length() - 1).strip();
        int comma = inner.indexOf(',');
        if (comma < 0) {
            if (!lowerInclusive || !upperInclusive) {
                throw refused(whole, "a single version is written in square brackets, [1.0]");
            }
            MavenVersion only = bound(whole, inner).orElseThrow(() -> refused(whole, "[] names no version"));
            return new Restriction(Optional.of(only), true, Optional.of(only), true);
        }
        Optional<MavenVersion> lower = bound(whole, inner.substring(0, comma));
        Optional<MavenVersion> upper = bound(whole, inner.substring(comma + 1));
        if (lower.isEmpty() && lowerInclusive || upper.isEmpty() && upperInclusive) {
            throw refused(whole, "an unbounded side is written with a parenthesis, (,2.0) or [1.0,)");
        }
        if (lower.isEmpty() && upper.isEmpty()) {
            throw refused(whole, "it bounds nothing and admits every version — bind component_present to ask for"
                    + " the package whatever its version");
        }
        if (lower.isPresent() && upper.isPresent()) {
            int order = lower.get().compareTo(upper.get());
            if (order > 0) {
                throw refused(whole, "its lower bound " + lower.get() + " is above its upper bound " + upper.get());
            }
            if (order == 0 && !(lowerInclusive && upperInclusive)) {
                throw refused(whole, "it admits no version — one version is written [" + lower.get() + "]");
            }
        }
        return new Restriction(lower, lowerInclusive, upper, upperInclusive);
    }

    private static Optional<MavenVersion> bound(String whole, String text) {
        String bound = text.strip();
        if (bound.isEmpty()) {
            return Optional.empty();
        }
        if (bound.contains(",") || bound.chars().anyMatch(c -> c == '[' || c == ']' || c == '(' || c == ')'
                || Character.isWhitespace(c) || Character.isISOControl(c))) {
            throw refused(whole, "\"" + BoundedText.clip(bound, 40) + "\" is not a version");
        }
        return Optional.of(MavenVersion.of(bound));
    }

    private static InvalidInputException refused(String spec, String why) {
        return new InvalidInputException("The version range \"" + BoundedText.clip(spec, 60) + "\" does not read: "
                + why + ".");
    }
}
