package com.asmolabs.vectispire.common.domain.checklists;

/**
 * A test-suite rule's glob over a suite's whole name: {@code *} any run of characters, {@code ?} one,
 * every other character itself — {@code com.example.arch.*} matches {@code com.example.arch.LayersTest}.
 *
 * <p>Matched by hand rather than turned into a regular expression: a suite name is the report's, a
 * pattern is a person's, and neither is handed to a regex engine whose backtracking a crafted pattern
 * could make run for minutes. This walk backtracks to the last star only.
 */
final class SuitePattern {

    private final String pattern;

    private SuitePattern(String pattern) {
        this.pattern = pattern;
    }

    static SuitePattern of(String pattern) {
        return new SuitePattern(pattern);
    }

    boolean matches(String name) {
        if (name == null) {
            return false;
        }
        int p = 0;
        int n = 0;
        int star = -1;
        int resume = 0;
        while (n < name.length()) {
            if (p < pattern.length() && (pattern.charAt(p) == '?' || pattern.charAt(p) == name.charAt(n))) {
                p++;
                n++;
            } else if (p < pattern.length() && pattern.charAt(p) == '*') {
                star = p++;
                resume = n;
            } else if (star >= 0) {
                p = star + 1;
                n = ++resume;
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
