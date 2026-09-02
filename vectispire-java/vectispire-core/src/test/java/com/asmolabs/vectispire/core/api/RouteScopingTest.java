package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Every <em>route</em> that names a target resolves an allowance — not every controller.
 *
 * <p><b>Why a second rule, when {@code AuthorizationCoverageTest} already exists.</b> That one
 * asks whether a <em>controller</em> mentions a {@code Visibility}, and it was written knowing it
 * could not do better. It then let one through: {@code GET /api/v1/inventory/versions} sat in a
 * controller that resolves an allowance for its sibling route, satisfied the rule, and returned
 * every component version in the estate to a reader given one repository. The rule was coarser
 * than the defect it watched, and the twenty-fourth leak walked through the gap.
 *
 * <p><b>Why route granularity is hard, and how this handles it.</b> Filtering usually runs through
 * a private helper — {@code requireVisible(principal, target)}, {@code visible(principal, id)} —
 * so a body-text scan for {@code Visibility} reports a route as unscoped when it is not. A first
 * attempt at this produced thirty candidates of which twenty-eight were false. The answer is a
 * naming convention, <b>checked rather than trusted</b>: a helper counts only if its own body
 * resolves an allowance. Calling a method {@code visibleThing()} does not buy anything.
 *
 * <p><b>What this still cannot prove.</b> That the allowance is <em>applied</em> to the query
 * rather than resolved and dropped. {@code VisibilityRoutesTest} answers that, per route, by
 * asking as a restricted reader. This is a lint whose whole job is that a new route cannot be
 * forgotten.
 */
@DisplayName("every route that names a target resolves an allowance")
class RouteScopingTest {

    private static final Path CONTROLLERS = Path.of("src/main/java/com/asmolabs/vectispire/core/api");

    private static final Pattern MAPPING = Pattern.compile("@(?:Get|Post|Put|Delete|Patch)Mapping");
    // An access modifier is required, so `@ResponseStatus(HttpStatus.CREATED)` between the
    // mapping and the method is not mistaken for the method itself — the first draft reported
    // three routes named `ResponseStatus`.
    private static final Pattern SIGNATURE = Pattern.compile(
            "\\b(?:public|private|protected)\\s[^;{()]*?\\b(\\w+)\\s*\\([^;{]*\\)\\s*(?:throws [\\w., ]+)?\\{");
    /** Any call, because which methods count is decided by reading them, not by their names. */
    private static final Pattern CALL = Pattern.compile("\\b(\\w+)\\s*\\(");

    /** The things that, in a body, mean "an allowance was resolved here". */
    private static final Pattern RESOLVES_ALLOWANCE =
            Pattern.compile("Visibility\\b|visibility\\.of\\(|Visibilities\\.|allowanceOf\\(|\\.permits\\(");

    /**
     * Built from {@link AuthorizationMarkers}, which is the one place the set of markers is
     * written. It used to be spelled out here, and a marker added elsewhere left this rule
     * reporting every route that adopted it as unguarded.
     */
    private static final Pattern ROLE_GUARD =
            Pattern.compile(AuthorizationMarkers.roleGuardPattern());

    /**
     * Routes that name no target, with the reason for each.
     *
     * <p>Keyed {@code Controller#method}, and every value is a claim a reader can check. A list
     * that grew whenever the test went red would end up exempting the next leak.
     */
    private static final Map<String, String> NAMES_NO_TARGET = Map.ofEntries(
            // Threat intelligence about a CVE: the same record for every reader, and knowing it
            // says nothing about who runs the package. `EpssController#getPriorities`, which does
            // read the estate, resolves an allowance and is not here.
            Map.entry("EpssController#lookupCve", "a public CVE record, identical for every caller"),

            // Deployment-wide configuration and a static rule table. Neither takes a parameter;
            // the routes that *change* the policy carry `@RequiresSecurityLead`.
            Map.entry("LicenseController#getPolicy", "the deployment's licence policy, the same for everybody"),
            Map.entry("LicenseController#getCompatibilityMatrix", "a static compatibility table, no target read"),

            // Whether the advisor answers and which model does. It used to publish Ollama's
            // internal URL as well; that was removed rather than exempted.
            Map.entry("AiAdvisorController#getStatus", "the advisor's availability, no target read"),

            // Explains a published vulnerability from the identifier and hints the caller supplies.
            // Its sibling `explainIssue` takes an issue id, reads it, and resolves an allowance —
            // which is why that one is absent from this list.
            Map.entry("AiAdvisorController#explainCve", "explains a public CVE from what the caller passes in"));

    private record Route(String controller, String method, String body) {
        String id() {
            return controller + "#" + method;
        }
    }

    @Test
    @DisplayName("a route either states a role, resolves an allowance, or calls a helper that does")
    void everyRouteIsScopedOrExempt() throws IOException {
        List<Route> routes = new ArrayList<>();
        List<String> unscoped = new ArrayList<>();

        try (Stream<Path> files = Files.list(CONTROLLERS)) {
            for (Path file : files.filter(p -> p.getFileName().toString().endsWith("Controller.java")).toList()) {
                String name = file.getFileName().toString().replace(".java", "");
                // The controller-level exemptions are the same list, not a copy of it: a
                // controller that serves nothing target-scoped has no target-scoped routes.
                if (AuthorizationCoverageTest.NOT_TARGET_SCOPED.contains(name)) {
                    continue;
                }
                String source = Files.readString(file, StandardCharsets.UTF_8);

                // A class-level role guard settles every route it covers.
                String head = source.substring(0, Math.max(0, source.indexOf("public class")));
                if (ROLE_GUARD.matcher(head).find()) {
                    continue;
                }

                Set<String> trustedHelpers = helpersThatResolveAnAllowance(source);

                for (Route route : routesOf(name, source)) {
                    routes.add(route);
                    if (isScoped(route, trustedHelpers) || NAMES_NO_TARGET.containsKey(route.id())) {
                        continue;
                    }
                    unscoped.add(route.id());
                }
            }
        }

        assertThat(routes)
                .as("no routes were parsed: the path or the parser is wrong, and a rule that "
                        + "inspects nothing passes forever")
                .hasSizeGreaterThan(60);

        assertThat(unscoped)
                .as("these routes serve data without stating who may see it. Resolve a Visibility, "
                        + "call a helper named requireVisible…/visible…/allowanceOf… that does, or "
                        + "carry a role guard — and if the route genuinely names no target, add it "
                        + "to NAMES_NO_TARGET with the reason")
                .isEmpty();
    }

    /**
     * Methods in this controller whose own body resolves an allowance.
     *
     * <p><b>This is the whole rule, and it is why no naming convention is imposed.</b> A helper
     * earns trust by what it does; a name would only have to be typed correctly. The check is
     * one level deep on purpose — a helper that delegates to another helper is rare here, and a
     * transitive walk would trade a false positive for a false negative, which is the worse of
     * the two for a security lint.
     */
    private static Set<String> helpersThatResolveAnAllowance(String source) {
        Set<String> trusted = new LinkedHashSet<>();
        Matcher declaration = Pattern.compile(
                "\\b(?:private|protected|public)\\s[^;{()=]*?\\b(\\w+)\\s*\\([^;{]*\\)\\s*(?:throws [\\w., ]+)?\\{")
                .matcher(source);

        while (declaration.find()) {
            String body = bodyFrom(source, declaration.end() - 1);
            if (body != null && RESOLVES_ALLOWANCE.matcher(body).find()) {
                trusted.add(declaration.group(1));
            }
        }
        return trusted;
    }

    private static boolean isScoped(Route route, Set<String> trustedHelpers) {
        if (RESOLVES_ALLOWANCE.matcher(route.body()).find()) {
            return true;
        }
        Matcher called = CALL.matcher(route.body());
        while (called.find()) {
            if (trustedHelpers.contains(called.group(1))) {
                return true;
            }
        }
        return false;
    }

    /** Every mapped method, with its annotation block and its body. */
    private static List<Route> routesOf(String controller, String source) {
        List<Route> routes = new ArrayList<>();
        Matcher mapping = MAPPING.matcher(source);

        while (mapping.find()) {
            Matcher signature = SIGNATURE.matcher(source);
            if (!signature.find(mapping.end())) {
                continue;
            }
            // **From the end of the previous member, not from the mapping.** A guard is as often
            // written above `@PostMapping` as below it, and reading only downwards reported five
            // `@RequiresSecurityLead` routes as unguarded.
            String decorations = source.substring(previousMemberEnd(source, mapping.start()), signature.start());
            if (ROLE_GUARD.matcher(decorations).find()) {
                continue;
            }
            String body = bodyFrom(source, signature.end() - 1);
            if (body != null) {
                routes.add(new Route(controller, signature.group(1), decorations + body));
            }
        }
        return routes;
    }

    /** Where the previous member ended, so a route's whole annotation block is in view. */
    private static int previousMemberEnd(String source, int mappingStart) {
        int brace = source.lastIndexOf('}', mappingStart);
        int semicolon = source.lastIndexOf(';', mappingStart);
        return Math.max(0, Math.max(brace, semicolon));
    }

    /** The balanced block starting at {@code open}, so a nested lambda does not end the method. */
    private static String bodyFrom(String source, int open) {
        int index = source.indexOf('{', open);
        if (index < 0) {
            return null;
        }
        int depth = 0;
        for (int i = index; i < source.length(); i++) {
            char c = source.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}' && --depth == 0) {
                return source.substring(index, i + 1);
            }
        }
        return null;
    }
}
