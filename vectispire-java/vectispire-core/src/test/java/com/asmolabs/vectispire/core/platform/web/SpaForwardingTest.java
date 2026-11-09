package com.asmolabs.vectispire.core.platform.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * The deep links the server hands to the interface. The configuration is active only when the interface is bundled,
 * which no backend test does, so its patterns are checked here as Spring reads them — against the interface's own
 * routes, so that a route deeper than the patterns fails the build instead of answering 404 to a refresh.
 */
@DisplayName("the interface's deep links")
class SpaForwardingTest {

    private static final Path ROUTES = Path.of("../../vectispire-angular/src/app.routes.ts");

    private static boolean forwarded(String path) {
        PathContainer container = PathContainer.parsePath(path);
        return SpaForwarding.PATTERNS.stream().anyMatch(pattern -> PathPatternParser.defaultInstance.parse(pattern)
                .matches(container));
    }

    @Test
    @DisplayName("every route of app.routes.ts is forwarded, its parameters filled in")
    void everyRoute() throws IOException {
        Matcher paths = Pattern.compile("path: '([^']*)'").matcher(Files.readString(ROUTES));
        List<String> routes = paths.results().map(match -> match.group(1))
                .filter(route -> !route.isEmpty() && !route.equals("**"))
                .map(route -> "/" + route.replaceAll(":[A-Za-z]+", "42"))
                .toList();

        assertThat(routes).as("the routes file was read").hasSizeGreaterThan(20).contains("/projects/42/checklist");
        assertThat(routes).allSatisfy(route -> assertThat(forwarded(route)).as(route).isTrue());
    }

    @Test
    @DisplayName("an asset, an API path and the actuator are never forwarded, at any depth")
    void neverForwarded() {
        assertThat(forwarded("/main-ABC123.js")).isFalse();
        assertThat(forwarded("/assets/logo.svg")).isFalse();
        assertThat(forwarded("/assets/i18n/fr.json")).isFalse();
        assertThat(forwarded("/api/v1")).isFalse();
        assertThat(forwarded("/api/v1/no-such-route")).isFalse();
        assertThat(forwarded("/actuator/health")).isFalse();
        assertThat(forwarded("/scim/v2/Users")).isFalse();
    }
}
