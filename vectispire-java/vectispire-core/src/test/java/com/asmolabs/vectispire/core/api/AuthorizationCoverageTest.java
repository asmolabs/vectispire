package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Every controller that serves target-scoped data resolves an allowance.
 *
 * <p><b>This exists because sweeping by hand does not converge.</b> Twenty routes were found and
 * closed by reading the controller surface; the attack path visualiser then shipped without an
 * allowance within hours, and a further sweep found the licence inventory and the ticket list.
 * Twenty-three holes, three separate passes, one person each time. The recommendation to encode
 * the rule was made twice before it was written down.
 *
 * <p><b>The rule.</b> A controller either states who may reach it by role — administrator, or
 * security lead, both of whom see the whole estate by construction — or it resolves a
 * {@link com.asmolabs.vectispire.common.domain.access.Visibility} for the caller. What is
 * forbidden is the third thing: {@code @RequiresAccount} alone over data that belongs to a
 * target, which is what every one of the twenty-three was.
 *
 * <p><b>Read as text rather than by reflection, deliberately.</b> The question is whether the
 * source names an allowance, not whether some code path happens to construct one at runtime; a
 * reflective check would pass on a controller that resolves a {@code Visibility} and then ignores
 * it. This is a lint, and it is honest about being one: it cannot prove the allowance is
 * *applied*. {@code VisibilityRoutesTest} does that, per route, by asking as a restricted reader.
 * What this adds is that a new controller cannot be forgotten — the failure it prevents is
 * nobody thinking to write that test at all.
 */
@DisplayName("the authorization surface")
class AuthorizationCoverageTest {

    private static final Path CONTROLLERS = Path.of(
            "src/main/java/com/asmolabs/vectispire/core/api");

    /**
     * Controllers that serve nothing belonging to a scan target, with the reason for each.
     *
     * <p><b>Shared with {@link RouteScopingTest}</b>, which works one level finer. Two copies of a
     * security exemption list is one copy that goes stale, and the stale one is the one that
     * exempts the next leak.
     *
     * <p><b>Every entry is a claim somebody can check, which is why none of them says "admin".</b>
     * A list that grew by adding a name whenever the test went red would end up exempting the next
     * leak. Adding to it should feel like an argument, because it is one.
     */
    static final Set<String> NOT_TARGET_SCOPED = Set.of(
            // Identity and session: about the caller, not about a target.
            "AuthController",
            // The account's own preferences and the deployment's settings; the routes that change
            // a setting carry `@RequiresAdministrator` of their own.
            "SettingsController",
            // Signing material and the public key a user verifies a release with — the same for
            // everybody, by design.
            "CryptoController",
            // The agent protocol. An agent is authenticated by its own key and given work already
            // narrowed by the queue's label routing; it never reads a backlog.
            "AgentsController",
            // Inbound webhook from an external tracker, anonymous by necessity — the caller is
            // Jira, which holds no session. It matches on a ticket reference the tracker already
            // knew and never enumerates.
            "TicketingWebhookController",
            // Notification channels are deployment configuration; the route that sends a test
            // message carries `@RequiresSecurityLead`.
            "NotificationCenterController",
            // Framework plumbing rather than a surface: error rendering and SPA forwarding.
            "ApiExceptionHandler",
            "SpaForwardingController");

    @Test
    @DisplayName("no controller serves target-scoped data on @RequiresAccount alone")
    void everyTargetScopedControllerResolvesAnAllowance() throws IOException {
        List<String> offenders = new ArrayList<>();
        List<String> inspected = new ArrayList<>();

        try (Stream<Path> files = Files.list(CONTROLLERS)) {
            for (Path file : files.filter(p -> p.getFileName().toString().endsWith("Controller.java")).toList()) {
                String name = file.getFileName().toString().replace(".java", "");
                inspected.add(name);
                if (NOT_TARGET_SCOPED.contains(name)) {
                    continue;
                }

                String source = Files.readString(file, StandardCharsets.UTF_8);

                // A role that sees everything by construction is an allowance, stated differently.
                boolean guardedByRole = source.contains("@RequiresAdministrator")
                        || source.contains("@RequiresSecurityLead")
                        || source.contains("@RequiresAgentKey");
                boolean resolvesAllowance = source.contains("VisibilityService")
                        || source.contains("Visibilities.");

                if (!guardedByRole && !resolvesAllowance) {
                    offenders.add(name);
                }
            }
        }

        // Guards the rule against silently checking nothing — the failure mode that let three of
        // this project's own assertions pass for a year without ever being able to fail.
        assertThat(inspected)
                .as("no controller sources were read: the path in this test is wrong, and a rule "
                        + "that inspects nothing passes forever")
                .hasSizeGreaterThan(30);

        assertThat(offenders)
                .as("these controllers serve data belonging to scan targets while requiring only a "
                        + "session, which is how a reader assigned one repository receives every "
                        + "other one's. Resolve a Visibility for the caller and refuse a target "
                        + "they were not given — or, if the controller genuinely serves nothing "
                        + "target-scoped, add it to NOT_TARGET_SCOPED with the reason")
                .isEmpty();
    }
}
