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
        String regexCodePath = toParamRegex(codePath);
        for (String dec : declaredPaths) {
            if (dec.matches(regexCodePath) || codePath.matches(toParamRegex(dec))) {
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
     * The path as a pattern in which each parameter matches one segment and everything else matches
     * itself.
     *
     * <p><b>Everything else quoted.</b> The paths come from the scanned repository — its routes and its
     * contracts — and were spliced into the pattern as written: a {@code .} matched any character, so
     * {@code /a.b} documented {@code /aXb}, and a route spelling a quantifier or a group made the match
     * mean something else, or cost as much as its author wished.
     */
    private static String toParamRegex(String path) {
        StringBuilder regex = new StringBuilder("^");
        Matcher parameter = PARAMETER.matcher(path);
        int literalFrom = 0;
        while (parameter.find()) {
            regex.append(Pattern.quote(path.substring(literalFrom, parameter.start()))).append("[^/]+");
            literalFrom = parameter.end();
        }
        return regex.append(Pattern.quote(path.substring(literalFrom))).append('$').toString();
    }
}
