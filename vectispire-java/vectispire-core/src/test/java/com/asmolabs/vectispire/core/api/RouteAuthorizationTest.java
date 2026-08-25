package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.api.security.OpenToAnonymous;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.api.security.RequiresAgentKey;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * Every route says who may call it, on the route.
 *
 * <p><b>The filter chain is not enough, and this is the argument.</b>
 * {@code SecurityConfiguration} ends in {@code anyRequest().authenticated()}, so today nothing
 * is open by accident. But a chain is a list of patterns read in order: the day somebody opens
 * one route with a {@code permitAll} written a little too wide, six others go with it, and
 * nothing anywhere says so. A rule stated on the handler cannot be widened from a distance.
 *
 * <p>This walks the mappings Spring actually registered — not the source — so a route added by
 * a new controller is in scope the moment it exists, with no list to remember to update.
 */
@DisplayName("every route declares who may call it")
class RouteAuthorizationTest extends ApiTestBase {

    private static final List<Class<? extends Annotation>> MARKERS =
            List.of(
                    RequiresAdministrator.class,
                    RequiresSecurityLead.class,
                    RequiresAccount.class,
                    RequiresAgentKey.class,
                    OpenToAnonymous.class);

    /**
     * The MVC mapping by name: Actuator registers a second one for its own endpoints, and
     * "expected one, found two" is not a useful thing to discover here.
     */
    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    private RequestMappingHandlerMapping mappings;

    @Test
    @DisplayName("no handler is left without one of the four markers")
    void everyHandlerIsMarked() {
        List<String> unmarked = new ArrayList<>();

        mappings.getHandlerMethods().forEach((info, handler) -> {
            if (!isOurs(handler)) {
                return;
            }
            if (MARKERS.stream().noneMatch(marker -> carries(handler, marker))) {
                unmarked.add(describe(info, handler));
            }
        });

        assertThat(unmarked)
                .as("a route with no marker is reachable on whatever the filter chain happens to "
                        + "say — add @RequiresAccount, @RequiresAdministrator, @RequiresAgentKey "
                        + "or @OpenToAnonymous")
                .isEmpty();
    }

    @Test
    @DisplayName("the routes open to anonymous callers are the listed ones, and each has a reason")
    void onlyTheWaysInAreOpen() {
        List<String> open = new ArrayList<>();
        mappings.getHandlerMethods().forEach((info, handler) -> {
            if (isOurs(handler) && carries(handler, OpenToAnonymous.class)) {
                open.add(String.valueOf(info.getPathPatternsCondition()));
            }
        });

        // A further one is not forbidden — it is a review conversation, and this failing is how
        // the conversation starts. Each of the ones below is anonymous because it runs *before*
        // there is a session to present, or because it is public by construction:
        //
        //   login            — the password exchange itself.
        //   methods          — which buttons the login screen should offer. Nothing sensitive: an
        //                      instance having single sign-on is public by construction, since
        //                      the redirect it produces is.
        //   session/exchange — trades the one-time hand-off cookie the browser just received for
        //                      the session it stands for. It cannot require the session it is on
        //                      the way to producing, and the cookie is the credential.
        //   mfa/verify       — the second half of that same exchange. It is called with the
        //                      `mfa_token` step 1 returned and no bearer, because the bearer is
        //                      what it is on the way to issuing.
        //   badge.svg        — a shield rendered into READMEs and pull requests, which are read
        //                      by people who have no account here.
        //   public-key.pub   — a public key. Publishing it is the point.
        //   tickets/webhook  — called by Jira, GitLab and ServiceNow, which hold a shared
        //                      secret rather than a session; the handler verifies it.
        //
        // **Listing them is not enough** — the day one of these is missing from the chain's
        // permitAll list it answers 401 and this test stays green. That is what
        // `anOpenRouteIsReallyReachableWithoutCredentials` is for, and it is how the MFA
        // lockout was eventually found.
        //
        assertThat(open).containsExactlyInAnyOrder(
                "[/api/v1/auth/login]",
                "[/api/v1/auth/methods]",
                "[/api/v1/auth/session/exchange]",
                "[/api/v1/auth/mfa/verify]",
                "[/api/v1/scorecards/repositories/{repoId}/badge.svg]",
                "[/api/v1/crypto/public-key.pub]",
                "[/api/v1/tickets/webhook/{provider}]");
    }

    @Test
    @DisplayName("the administrator expression and the enum's idea of an administrator agree")
    void theAdministrativeRolesAreTheSameInBothPlaces() {
        String expression = RequiresAdministrator.class.getAnnotation(PreAuthorize.class).value();

        for (Role role : Role.values()) {
            boolean named = expression.contains("'" + role.name() + "'");
            assertThat(named)
                    .as("%s is %sadministrative in Role, so it should %sbe in the expression",
                            role, role.isAdministrative() ? "" : "not ", role.isAdministrative() ? "" : "not ")
                    .isEqualTo(role.isAdministrative());
        }
    }

    @Test
    @DisplayName("a route marked for administrators is refused to an ordinary account")
    void administratorRoutesRefuseAReader() throws Exception {
        // One concrete probe behind the enumeration: the annotations above prove the rule is
        // *stated*, and this proves method security is switched on at all. Without it, every
        // marker could be decorative and the suite would still be green.
        mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/users"),
                        asReader()))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden());

        mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/users"),
                        asCiso()))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden());

        mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/users"),
                        asAdmin()))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());
    }

    @Test
    @DisplayName("security lead routes permit CISO and administrators, but refuse reader")
    void securityLeadRoutesPermitCisoAndAdmin() throws Exception {
        mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/gate/policies"),
                        asReader()))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden());

        mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/gate/policies"),
                        asCiso()))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

        mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/gate/policies"),
                        asAdmin()))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());
    }

    /**
     * The probe the enumeration above cannot be.
     *
     * <p><b>Why this exists.</b> {@code /api/v1/auth/mfa/verify} carried {@code
     * @OpenToAnonymous} and was <em>not</em> in the chain's {@code permitAll} list, so it fell
     * to {@code anyRequest().authenticated()} and answered 401 before the controller was
     * entered: every account with MFA enabled was locked out. The suite stayed green the whole
     * time, because {@link #onlyTheWaysInAreOpen()} reads the annotation and the annotation was
     * right. An annotation is a statement about intent; only a request through the real chain
     * is a statement about behaviour.
     *
     * <p><b>The assertion is "a handler was reached", not "the status is not 401".</b> A route
     * that is open to anonymous callers may still legitimately answer 401 from inside the
     * handler — {@code /auth/login} does exactly that on bad credentials, and so does {@code
     * session/exchange} on a stale cookie. Those are answers; a chain rejection is the absence
     * of one. {@code MvcResult#getHandler()} tells them apart: the dispatcher records the
     * handler at lookup time, so it is non-null whenever the request got that far and null
     * whenever a filter short-circuited first.
     *
     * <p>It walks the mappings rather than a list, so a seventh open route is covered the day
     * it is annotated, with nothing to remember.
     */
    @Test
    @DisplayName("an open route is really reachable without credentials, chain included")
    void anOpenRouteIsReallyReachableWithoutCredentials() throws Exception {
        List<String> unreachable = new ArrayList<>();

        for (var entry : mappings.getHandlerMethods().entrySet()) {
            RequestMappingInfo info = entry.getKey();
            HandlerMethod handler = entry.getValue();
            if (!isOurs(handler) || !carries(handler, OpenToAnonymous.class)) {
                continue;
            }

            HttpMethod method = firstMethodOf(info);
            for (String pattern : patternsOf(info)) {
                // A path variable's value is irrelevant here: what is under test is whether the
                // chain let the request through, and it decides on the pattern, not the value.
                String path = pattern.replaceAll("\\{[^}]+}", "1");

                MvcResult result = mvc.perform(
                                org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                        .request(method, path))
                        .andReturn();

                if (result.getHandler() == null) {
                    unreachable.add(method + " " + pattern
                            + " → refused by the filter chain with "
                            + result.getResponse().getStatus());
                }
            }
        }

        assertThat(unreachable)
                .as("these routes declare @OpenToAnonymous but the filter chain stops them "
                        + "before the controller — add a matching permitAll in "
                        + "SecurityConfiguration, or drop the annotation")
                .isEmpty();
    }

    /** Empty means "every method": the mapping declared no restriction, so GET will do. */
    private static HttpMethod firstMethodOf(RequestMappingInfo info) {
        return info.getMethodsCondition().getMethods().stream()
                .findFirst()
                .map(requestMethod -> HttpMethod.valueOf(requestMethod.name()))
                .orElse(HttpMethod.GET);
    }

    private static Set<String> patternsOf(RequestMappingInfo info) {
        var patterns = info.getPathPatternsCondition();
        return patterns == null ? Set.of() : patterns.getPatternValues();
    }

    private static boolean isOurs(HandlerMethod handler) {
        return handler.getBeanType().getPackageName().startsWith("com.asmolabs.vectispire.core.api");
    }

    /** Method first, then the class: a method's own marker is the one that applies. */
    private static boolean carries(HandlerMethod handler, Class<? extends Annotation> marker) {
        Method method = handler.getMethod();
        return method.getAnnotation(marker) != null || handler.getBeanType().getAnnotation(marker) != null;
    }

    private static String describe(RequestMappingInfo info, HandlerMethod handler) {
        return String.valueOf(info.getMethodsCondition()).toUpperCase(Locale.ROOT)
                + " " + info.getPathPatternsCondition()
                + " → " + handler.getBeanType().getSimpleName() + "." + handler.getMethod().getName();
    }
}
