package com.asmolabs.vectispire.common.domain.apis;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reconciles discovered code endpoints against declared API contracts.
 */
public record ShadowApiDiff(
        List<ApiEndpoint> documentedEndpoints,
        List<ApiEndpoint> shadowEndpoints,
        List<String> zombieEndpoints) {

    public static ShadowApiDiff compute(List<ApiEndpoint> codeEndpoints, List<ApiContract> contracts) {
        if (codeEndpoints == null) {
            codeEndpoints = List.of();
        }
        if (contracts == null || contracts.isEmpty()) {
            // No contracts declared: all code endpoints are considered undocumented / shadow
            return new ShadowApiDiff(List.of(), codeEndpoints, List.of());
        }

        Set<String> declaredPaths = new HashSet<>();
        for (ApiContract contract : contracts) {
            if (contract.declaredPaths() != null) {
                for (String p : contract.declaredPaths()) {
                    declaredPaths.add(normalizePath(p));
                }
            }
        }

        List<ApiEndpoint> documented = new ArrayList<>();
        List<ApiEndpoint> shadow = new ArrayList<>();
        Set<String> matchedDeclaredPaths = new HashSet<>();

        for (ApiEndpoint ep : codeEndpoints) {
            String norm = normalizePath(ep.path());
            if (matchesAnyDeclared(norm, declaredPaths, matchedDeclaredPaths)) {
                documented.add(ep);
            } else {
                shadow.add(ep);
            }
        }

        List<String> zombie = new ArrayList<>();
        for (String dec : declaredPaths) {
            if (!matchedDeclaredPaths.contains(dec)) {
                zombie.add(dec);
            }
        }

        return new ShadowApiDiff(List.copyOf(documented), List.copyOf(shadow), List.copyOf(zombie));
    }

    private static boolean matchesAnyDeclared(String codePath, Set<String> declaredPaths, Set<String> matched) {
        if (declaredPaths.contains(codePath)) {
            matched.add(codePath);
            return true;
        }
        // Match parameterized paths like /users/{id} vs /users/:id or /users/{userId}
        for (String dec : declaredPaths) {
            if (fits(dec, codePath) || fits(codePath, dec)) {
                matched.add(dec);
                return true;
            }
        }
        return false;
    }

    private static String normalizePath(String path) {
        if (path == null || path.isBlank()) return "/";
        String trimmed = path.trim();
        if (!trimmed.startsWith("/")) trimmed = "/" + trimmed;
        if (trimmed.length() > 1 && trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    /** A path parameter, in either spelling: {@code {id}} or {@code :id}. */
    private static final Pattern PARAMETER = Pattern.compile("\\{[^/}]+\\}|:[a-zA-Z0-9_]+");

    /**
     * Past this length a path is only ever compared as written. A route longer than this is not a
     * route anybody declares, and it bounds what one comparison may cost.
     */
    static final int MAX_TEMPLATE_LENGTH = 512;

    /** In a compiled segment: one character, whatever it is — a parameter's first. */
    private static final int ANY_ONE = -1;
    /** In a compiled segment: any run of characters, the empty one included — a parameter's rest. */
    private static final int ANY_RUN = -2;

    /**
     * Whether {@code path} is one of the paths {@code template} describes: the same number of
     * segments, and in each a parameter standing for one or more characters, everything else for
     * itself.
     *
     * <p><b>Everything else literal.</b> The paths come from the scanned repository — its routes and its
     * contracts — and were spliced into a regex as written: a {@code .} matched any character, so
     * {@code /a.b} documented {@code /aXb}, and a route spelling a quantifier or a group made the match
     * mean something else, or cost as much as its author wished.
     *
     * <p><b>Segment by segment, without a regex.</b> Quoting the literals was not enough: adjacent
     * parameters ({@code /{a}{b}{c}}) became {@code [^/]+[^/]+[^/]+}, which a regex engine backtracks
     * through in time exponential in their number, on a path the scanned repository also wrote. Each
     * segment is matched by the two-pointer wildcard walk, at most the product of the two lengths, and
     * those lengths are bounded.
     */
    static boolean fits(String path, String template) {
        if (path.length() > MAX_TEMPLATE_LENGTH || template.length() > MAX_TEMPLATE_LENGTH) {
            return false;
        }
        String[] segments = path.split("/", -1);
        String[] templates = template.split("/", -1);
        if (segments.length != templates.length) {
            return false;
        }
        for (int i = 0; i < segments.length; i++) {
            if (!segmentFits(segments[i], compile(templates[i]))) {
                return false;
            }
        }
        return true;
    }

    private static int[] compile(String segment) {
        List<Integer> tokens = new ArrayList<>();
        Matcher parameter = PARAMETER.matcher(segment);
        int literalFrom = 0;
        while (parameter.find()) {
            segment.substring(literalFrom, parameter.start()).chars().forEach(tokens::add);
            tokens.add(ANY_ONE);
            tokens.add(ANY_RUN);
            literalFrom = parameter.end();
        }
        segment.substring(literalFrom).chars().forEach(tokens::add);
        return tokens.stream().mapToInt(Integer::intValue).toArray();
    }

    /** The wildcard walk: on a mismatch, give the last run one more character and resume after it. */
    private static boolean segmentFits(String text, int[] pattern) {
        int t = 0;
        int p = 0;
        int run = -1;
        int resumeAt = 0;
        while (t < text.length()) {
            if (p < pattern.length && (pattern[p] == ANY_ONE || pattern[p] == text.charAt(t))) {
                t++;
                p++;
            } else if (p < pattern.length && pattern[p] == ANY_RUN) {
                run = p++;
                resumeAt = t;
            } else if (run >= 0) {
                p = run + 1;
                t = ++resumeAt;
            } else {
                return false;
            }
        }
        while (p < pattern.length && pattern[p] == ANY_RUN) {
            p++;
        }
        return p == pattern.length;
    }
}
