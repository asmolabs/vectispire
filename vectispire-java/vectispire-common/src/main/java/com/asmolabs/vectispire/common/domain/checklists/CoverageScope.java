package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The packages a {@code coverage_threshold} rule measures, when it measures fewer than the whole report
 * — the organisation's decision, stated in the template (decision 0032, amendment of 2026-10-03).
 *
 * <h2>Over paths, not package names</h2>
 *
 * <p>A coverage import keeps each package as a path ({@code CoveragePackages}): a JaCoCo or Cobertura
 * package {@code org.example.service} is {@code org/example/service}, an lcov file is counted in its
 * directory, the top level is the empty path. The patterns are written over those paths, so one scope
 * reads the same over a Java report and a TypeScript one. A pattern that reads like a dotted package
 * name is refused rather than left to match nothing: {@code org.example.service} is written {@code
 * org/example/service}.
 *
 * <h2>Two wildcards</h2>
 *
 * <ul>
 *   <li>{@code **}, a whole segment: any number of segments, none included — {@code **}{@code /service/**}
 *       matches {@code service}, {@code org/example/service} and {@code org/example/service/impl}.
 *   <li>{@code *} inside a segment: any run of characters but {@code /} — {@code org/example/*-api}.
 * </ul>
 *
 * <p>A pattern without a wildcard names one package, not its subpackages: {@code org/example} is that
 * package alone, {@code org/example/**} is it and everything under it. Nothing else is a wildcard; {@code
 * ?}, brackets and braces are refused rather than read literally, since a reader would take them for
 * wildcards. Matching is case-sensitive, as the reports' paths are.
 *
 * <p>A package is in the scope when it matches an {@code include} pattern — every package when none is
 * given — and no {@code exclude} pattern.
 *
 * @param include sorted, possibly empty: every package
 * @param exclude sorted, possibly empty
 */
public record CoverageScope(List<String> include, List<String> exclude) {

    public static final int MAX_PATTERNS = 20;
    public static final int MAX_PATTERN = ChecklistRule.MAX_PATTERN;

    public CoverageScope {
        include = patterns(include, "include");
        exclude = patterns(exclude, "exclude");
        if (include.isEmpty() && exclude.isEmpty()) {
            throw new InvalidInputException("A coverage scope names at least one pattern, in include or exclude; "
                    + "leave the scope out to measure the whole report.");
        }
    }

    /** Whether a package's path is in the scope. */
    public boolean matches(String path) {
        String[] segments = path.isEmpty() ? new String[0] : path.split("/", -1);
        boolean included = include.isEmpty() || include.stream().anyMatch(pattern -> matches(pattern, segments));
        return included && exclude.stream().noneMatch(pattern -> matches(pattern, segments));
    }

    /** The scope as a reader of a measurement or a signed document reads it, beside the figure. */
    public String describe() {
        String included = include.isEmpty() ? "every package" : "packages matching " + String.join(", ", include);
        return exclude.isEmpty() ? included : included + ", excluding " + String.join(", ", exclude);
    }

    private static List<String> patterns(List<String> given, String what) {
        if (given == null) {
            return List.of();
        }
        if (given.size() > MAX_PATTERNS) {
            throw new InvalidInputException("A coverage scope's " + what + " holds at most " + MAX_PATTERNS
                    + " patterns.");
        }
        Set<String> seen = new LinkedHashSet<>();
        for (String pattern : given) {
            String checked = check(pattern, what);
            if (!seen.add(checked)) {
                throw new InvalidInputException("The pattern \"" + BoundedText.clip(checked, 60) + "\" is in " + what
                        + " twice.");
            }
        }
        return seen.stream().sorted().toList();
    }

    /** One pattern, refused in words when it is not one this reads the way its writer meant. */
    static String check(String raw, String what) {
        String pattern = raw == null ? "" : raw.strip();
        String quoted = "\"" + BoundedText.clip(pattern, 60) + "\"";
        if (pattern.isEmpty()) {
            throw new InvalidInputException("A pattern in the coverage scope's " + what + " is empty.");
        }
        if (pattern.length() > MAX_PATTERN || pattern.chars().anyMatch(Character::isISOControl)) {
            throw new InvalidInputException("A coverage scope's pattern is 1 to " + MAX_PATTERN
                    + " characters, without control characters.");
        }
        if (pattern.indexOf('\\') >= 0) {
            throw new InvalidInputException("The pattern " + quoted + " carries a backslash: segments are separated "
                    + "by /, whatever the system the report was written on.");
        }
        for (char wildcard : new char[] {'?', '[', ']', '{', '}', '!'}) {
            if (pattern.indexOf(wildcard) >= 0) {
                throw new InvalidInputException("The pattern " + quoted + " carries \"" + wildcard + "\": only * (within "
                        + "a segment) and ** (any number of segments) are wildcards here.");
            }
        }
        if (pattern.startsWith("/") || pattern.endsWith("/") || pattern.contains("//")) {
            throw new InvalidInputException("The pattern " + quoted + " has an empty segment: package paths have no "
                    + "leading or trailing slash — write **/ to match anywhere, /** for everything below.");
        }
        if (pattern.indexOf('/') < 0 && pattern.indexOf('.') >= 0) {
            throw new InvalidInputException("The pattern " + quoted + " reads like a dotted package name; packages "
                    + "are matched as paths — write " + BoundedText.clip(pattern.replace('.', '/'), 60) + ".");
        }
        for (String segment : pattern.split("/", -1)) {
            if (segment.equals(".") || segment.equals("..")) {
                throw new InvalidInputException("The pattern " + quoted + " has a \"" + segment + "\" segment; a "
                        + "package path has none.");
            }
            if (segment.contains("**") && !segment.equals("**")) {
                throw new InvalidInputException("The pattern " + quoted + " uses ** inside a segment; ** stands for "
                        + "whole segments (**/service/**), * for characters within one (*-api).");
            }
        }
        return pattern;
    }

    /**
     * Segment by segment, {@code **} taking none or more: the furthest positions reachable in the path
     * after each pattern segment, so a pattern of a few dozen segments over a path of a few hundred never
     * backtracks exponentially.
     */
    static boolean matches(String pattern, String[] path) {
        String[] parts = pattern.split("/", -1);
        boolean[] reachable = new boolean[path.length + 1];
        reachable[0] = true;
        for (String part : parts) {
            boolean[] next = new boolean[path.length + 1];
            if (part.equals("**")) {
                boolean any = false;
                for (int i = 0; i <= path.length; i++) {
                    any |= reachable[i];
                    next[i] = any;
                }
            } else {
                for (int i = 0; i < path.length; i++) {
                    if (reachable[i] && segment(part, path[i])) {
                        next[i + 1] = true;
                    }
                }
            }
            reachable = next;
        }
        return reachable[path.length];
    }

    /** One segment against one {@code *}-pattern: greedy with a single backtrack point, linear. */
    static boolean segment(String pattern, String text) {
        int p = 0;
        int t = 0;
        int star = -1;
        int resume = 0;
        while (t < text.length()) {
            if (p < pattern.length() && pattern.charAt(p) == '*') {
                star = p++;
                resume = t;
            } else if (p < pattern.length() && pattern.charAt(p) == text.charAt(t)) {
                p++;
                t++;
            } else if (star >= 0) {
                p = star + 1;
                t = ++resume;
            } else {
                return false;
            }
        }
        while (p < pattern.length() && pattern.charAt(p) == '*') {
            p++;
        }
        return p == pattern.length();
    }
}
