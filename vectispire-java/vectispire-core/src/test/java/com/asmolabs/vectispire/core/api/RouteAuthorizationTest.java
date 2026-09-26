package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.web.security.OpenToAnonymous;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.RequiresAgentKey;
import com.asmolabs.vectispire.core.access.web.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.access.web.security.RequiresPlatformGovernor;
import com.asmolabs.vectispire.core.access.web.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.access.web.security.RequiresWriteAccount;
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

    private static final List<Class<? extends Annotation>> MARKERS = AuthorizationMarkers.ALL;

    /**
     * The MVC mapping by name: Actuator registers a second one for its own endpoints, and
     * "expected one, found two" is not a useful thing to discover here.
     */
    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    private RequestMappingHandlerMapping mappings;

    @Test
    @DisplayName("no handler is left without one of the eight markers")
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
                        + "say — add @RequiresAccount, @RequiresAdministrator, "
                        + "@RequiresSecurityLead, @RequiresGovernanceRead, @RequiresWriteAccount, "
                        + "@RequiresAgentKey "
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
        //   badges/{token}   — a shield rendered into READMEs and pull requests, which are read
        //                      by people who have no account here. **Named by a token and not by
        //                      the repository's id**: the id-addressed version of this route was
        //                      an anonymous walk through every repository's security grade, and
        //                      an existence oracle on top of it. A token names one repository
        //                      somebody deliberately published — see `BadgeRoutesTest`.
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
                "[/api/v1/scorecards/badges/{token}.svg]",
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
    @DisplayName("the governance read expression and the enum's idea of a global scope agree")
    void theGovernanceReadersAreTheSameInBothPlaces() {
        // **Reading the posture and seeing the estate are one privilege, and this says so.** What
        // these routes disclose is the security posture of every target there is; giving that to
        // an account whose visibility is three repositories would be a way around the scope
        // rather than a smaller version of it.
        String expression = RequiresGovernanceRead.class.getAnnotation(PreAuthorize.class).value();

        for (Role role : Role.values()) {
            boolean named = expression.contains("'" + role.name() + "'");
            assertThat(named)
                    .as("%s %s a global security scope in Role, so it should %sbe in the expression",
                            role,
                            role.hasGlobalSecurityScope() ? "has" : "does not have",
                            role.hasGlobalSecurityScope() ? "" : "not ")
                    .isEqualTo(role.hasGlobalSecurityScope());
        }
    }

    @Test
    @DisplayName("the security lead expression and the enum's idea of a governance writer agree")
    void theSecurityLeadRolesAreTheSameInBothPlaces() {
        // **The parity the administrator marker had and this one did not.** `Role` explains that
        // it carries its flags on the constant rather than in a second list, because two lists
        // over one set diverge — and then the expression below is that second list. The case
        // above holds the administrator pair together; this one holds the other pair, which was
        // free to drift.
        //
        // Paired with `canWriteGovernance` and not with `hasGlobalSecurityScope`, which is what it
        // used to mean. AUDITOR is exactly the role that separates the two: it sees the whole
        // estate and changes none of it, so a single flag can no longer answer both questions.
        String expression = RequiresSecurityLead.class.getAnnotation(PreAuthorize.class).value();

        for (Role role : Role.values()) {
            boolean named = expression.contains("'" + role.name() + "'");
            assertThat(named)
                    .as("%s %s write governance in Role, so it should %sbe in the expression",
                            role,
                            role.canWriteGovernance() ? "may" : "may not",
                            role.canWriteGovernance() ? "" : "not ")
                    .isEqualTo(role.canWriteGovernance());
        }
    }

    @Test
    @DisplayName("no route states its own role list instead of wearing a marker")
    void noHandlerSpellsOutItsOwnRoleList() throws Exception {
        // **Two routes used to.** `SettingsController` wrote `hasAnyRole('SUPERUSER', 'ADMIN',
        // 'CISO')` in full, twice, in inline `@PreAuthorize` annotations — a third copy of the
        // list that no test tied to anything, on the route that writes every platform setting.
        // The marker requirement above could not see them: the class carries `@RequiresAccount`,
        // so every handler in it was already marked, and the inline expression that narrowed them
        // was invisible to a check that only asks whether a marker is present.
        //
        // The rule is not "no `@PreAuthorize`" — the markers are themselves meta-annotated with
        // one. It is that a handler must not carry its own, because a marker can be kept in step
        // with `Role` and a literal cannot.
        List<String> spellingItOut = new ArrayList<>();
        for (HandlerMethod handler : mappings.getHandlerMethods().values()) {
            if (!isOurs(handler)) {
                continue;
            }
            // The method's own annotation, not one inherited from a marker: `getAnnotation` on the
            // method reports what is written there, and a meta-annotation on a marker is not.
            PreAuthorize direct = handler.getMethod().getAnnotation(PreAuthorize.class);
            if (direct != null) {
                spellingItOut.add(handler.getBeanType().getSimpleName() + "#" + handler.getMethod().getName()
                        + " → " + direct.value());
            }
        }

        assertThat(spellingItOut)
                .as("these handlers name roles directly; give them a marker instead, so `Role` "
                        + "stays the one place a role list is written")
                .isEmpty();
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

    @Test
    @DisplayName("the governor expression and the enum's idea of governing agree")
    void theGovernorsAreTheSameInBothPlaces() {
        String expression = RequiresPlatformGovernor.class.getAnnotation(PreAuthorize.class).value();

        for (Role role : Role.values()) {
            boolean named = expression.contains("'" + role.name() + "'");
            assertThat(named)
                    .as("%s %s govern the platform in Role, so it should %sbe in the expression",
                            role, role.governsPlatform() ? "does" : "does not",
                            role.governsPlatform() ? "" : "not ")
                    .isEqualTo(role.governsPlatform());
        }
    }

    @Test
    @DisplayName("the account that can lift the rule cannot act under it")
    void theGovernorCausesNoEffects() {
        // **The property that closes four-eyes, stated as an invariant and not as a list.** The
        // bypass was: switch the control off, settle alone, switch it back on. Removing the right to
        // approve would not have closed it — the service settles everyone's decision when the
        // setting is off. What closes it is that no role holds both halves at once.
        for (Role role : Role.values()) {
            if (role.governsPlatform()) {
                assertThat(role.canCauseEffects())
                        .as("%s can lift the rule: it must not be able to act under it", role)
                        .isFalse();
                assertThat(role.canApproveTriage())
                        .as("%s can lift the rule: approving would be the same hole", role)
                        .isFalse();
            }
        }
        assertThat(Role.values()).anyMatch(Role::governsPlatform);
    }

    @Test
    @DisplayName("the write expression and the enum's idea of causing an effect agree")
    void theWritersAreTheSameInBothPlaces() {
        // The widest marker of the set, and the one whose width is the point: triaging is ordinary
        // work, so an ordinary user belongs inside it. Only the account whose whole purpose is to
        // look sits outside.
        String expression = RequiresWriteAccount.class.getAnnotation(PreAuthorize.class).value();

        for (Role role : Role.values()) {
            boolean named = expression.contains("'" + role.name() + "'");
            assertThat(named)
                    .as("%s %s cause effects in Role, so it should %sbe in the expression",
                            role,
                            role.canCauseEffects() ? "may" : "may not",
                            role.canCauseEffects() ? "" : "not ")
                    .isEqualTo(role.canCauseEffects());
        }
    }

    @Test
    @DisplayName("an auditor reads the governance it is there to inspect")
    void anAuditorMayRead() throws Exception {
        // The reason the role exists. Before it, every one of these required a marker that also
        // granted the power to rewrite what it shows.
        for (String route : List.of(
                "/api/v1/audit-log", "/api/v1/gate/policies", "/api/v1/siem/config",
                "/api/v1/threat-intel/status", "/api/v1/rule-sets")) {
            mvc.perform(authenticated(
                            org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get(route),
                            asAuditor()))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                            .status().isOk());
        }
    }

    @Test
    @DisplayName("the catalogue preview, which clones GitHub to answer, is the security lead's")
    void theCataloguePreviewIsNotAReadersToTrigger() throws Exception {
        // Any governance reader could make the control plane clone the upstream on every request.
        // The preview prepares an import, and the import is a security lead's.
        mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/rule-sets/catalogue"),
                        asAuditor()))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden());
    }

    /**
     * The writing routes an auditor may call, each with the reason.
     *
     * <p>Every one acts on the caller's own account or session — never on the estate, a target or
     * the deployment. A route that changes anything else does not belong here, and this list growing
     * whenever the test goes red is exactly how the role would become a lie again: <b>adding to it
     * should feel like an argument, because it is one.</b> Keyed {@code METHOD pattern}.
     */
    private static final java.util.Map<String, String> AN_AUDITOR_MAY_CALL = java.util.Map.ofEntries(
            java.util.Map.entry("DELETE /api/v1/auth/session", "ends the caller's own session"),
            java.util.Map.entry("POST /api/v1/auth/change-password", "the caller's own password"),
            java.util.Map.entry("POST /api/v1/auth/mfa/setup", "enrols the caller's own second factor"),
            java.util.Map.entry("POST /api/v1/auth/mfa/enable", "enables the caller's own second factor"),
            java.util.Map.entry("POST /api/v1/auth/mfa/disable", "the caller's own second factor"),
            java.util.Map.entry("POST /api/v1/crypto/verify", "checks a signature against the instance's public key: a computation, nothing is written"));

    @Test
    @DisplayName("an auditor changes nothing: every writing route refuses it, but those about its own account")
    void anAuditorMayNotWrite() throws Exception {
        // **Derived from every non-GET route, not listed.** The hand-written list here named eight
        // routes; `POST /api/v1/gate` was not among them, carried `@RequiresAccount`, and let the
        // role that "changes nothing, anywhere" write verdicts into the register the evidence bundle
        // reads. A list of the writing routes is written by whoever forgot one.
        List<String> admitted = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        List<String> staleExemptions = new ArrayList<>();
        int probed = 0;
        for (var mapping : mappings.getHandlerMethods().entrySet()) {
            HandlerMethod handler = mapping.getValue();
            if (!isOurs(handler)
                    || carries(handler, OpenToAnonymous.class)
                    || carries(handler, RequiresAgentKey.class)) {
                // No account session is what reaches these: anonymous ways in, and the agent protocol.
                continue;
            }
            for (var requestMethod : mapping.getKey().getMethodsCondition().getMethods()) {
                if (requestMethod == org.springframework.web.bind.annotation.RequestMethod.GET
                        || requestMethod == org.springframework.web.bind.annotation.RequestMethod.HEAD
                        || requestMethod == org.springframework.web.bind.annotation.RequestMethod.OPTIONS) {
                    continue;
                }
                for (String pattern : patternsOf(mapping.getKey())) {
                    String key = requestMethod.name() + " " + pattern;
                    seen.add(key);
                    if (AN_AUDITOR_MAY_CALL.containsKey(key)) {
                        if (!markerAdmits(handler, Role.AUDITOR)) {
                            staleExemptions.add(key);
                        }
                        continue;
                    }
                    probed++;
                    // A marker that leaves the auditor out refuses it before the handler runs — but
                    // after the arguments bind, so a probe's `{}` can answer 400 first. The marker is
                    // the refusal, and method security itself is proven by the probes above. One
                    // that admits the auditor must be refused by what is behind it, over HTTP.
                    if (!markerAdmits(handler, Role.AUDITOR)) {
                        continue;
                    }
                    // A fresh session each time: a route that ended the session would otherwise turn
                    // every later refusal into a 401 and hide a 200 behind it.
                    int status = mvc.perform(authenticated(
                                    org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                            .request(HttpMethod.valueOf(requestMethod.name()), pattern.replaceAll("\\{[^}]+}", "1"))
                                            .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                                            .content("{}"),
                                    asAuditor()))
                            .andReturn().getResponse().getStatus();
                    if (status != 403) {
                        admitted.add(key + " answered " + status);
                    }
                }
            }
        }

        assertThat(probed)
                .as("no writing route was probed: the mapping walk is wrong, and a rule that checks "
                        + "nothing passes forever")
                .isGreaterThan(40);
        assertThat(seen)
                .as("an exemption naming no writing route exempts nothing and hides that it does")
                .containsAll(AN_AUDITOR_MAY_CALL.keySet());
        assertThat(staleExemptions)
                .as("exempted routes whose marker refuses the auditor anyway: remove the exemption")
                .isEmpty();
        assertThat(admitted)
                .as("an auditor sees the whole estate and changes none of it; these writing routes "
                        + "admitted one. Give them @RequiresWriteAccount (or a narrower marker) — or, "
                        + "if the route acts on the caller's own account only, add it to "
                        + "AN_AUDITOR_MAY_CALL with the reason")
                .isEmpty();

        // Widening the read marker must not have widened it to everybody: USER is still out.
        mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                .get("/api/v1/audit-log"),
                        asReader()))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .status().isForbidden());
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

    /**
     * Every handler of the control plane, wherever its controller lives: {@code core.api} for the
     * domains still packaged by layer, {@code core.<module>.web} for a vertical module (decision
     * 0028). Matching {@code core.api} alone would have exempted every controller the moment it moved
     * into a module — silently, since a handler this skips is a handler it never reports.
     */
    private static boolean isOurs(HandlerMethod handler) {
        return handler.getBeanType().getPackageName().startsWith("com.asmolabs.vectispire.core.");
    }

    /** Whether the marker that applies to this handler — the method's, else the class's — names the role. */
    private static boolean markerAdmits(HandlerMethod handler, Role role) {
        Annotation marker = MARKERS.stream()
                .<Annotation>map(type -> handler.getMethod().getAnnotation(type))
                .filter(java.util.Objects::nonNull)
                .findFirst()
                .or(() -> MARKERS.stream()
                        .<Annotation>map(type -> handler.getBeanType().getAnnotation(type))
                        .filter(java.util.Objects::nonNull)
                        .findFirst())
                .orElseThrow(() -> new AssertionError("unmarked handler " + handler));
        PreAuthorize expression = marker.annotationType().getAnnotation(PreAuthorize.class);
        // `@RequiresAccount` is `isAuthenticated()`: every role.
        return expression == null
                || !expression.value().contains("hasAnyRole")
                || expression.value().contains("'" + role.name() + "'");
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
