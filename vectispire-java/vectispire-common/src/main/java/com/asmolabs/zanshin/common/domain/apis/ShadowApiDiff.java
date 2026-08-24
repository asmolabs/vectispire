package com.asmolabs.zanshin.common.domain.apis;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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

    private static String toParamRegex(String path) {
        // Replace {param} or :param with regex pattern [^/]+
        return "^" + path.replaceAll("\\{[^/]+\\}", "[^/]+")
                .replaceAll(":[a-zA-Z0-9_]+", "[^/]+") + "$";
    }
}
