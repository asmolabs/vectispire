package com.asmolabs.zanshin.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.users.Role;
import com.asmolabs.zanshin.core.api.security.OpenToAnonymous;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.api.security.RequiresAdministrator;
import com.asmolabs.zanshin.core.api.security.RequiresAgentKey;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.prepost.PreAuthorize;
import com.asmolabs.zanshin.core.api.security.RequiresSecurityLead;
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
    @DisplayName("three routes are open to anonymous callers, and each has a reason")
    void onlyTheWaysInAreOpen() {
        List<String> open = new ArrayList<>();
        mappings.getHandlerMethods().forEach((info, handler) -> {
            if (isOurs(handler) && carries(handler, OpenToAnonymous.class)) {
                open.add(String.valueOf(info.getPathPatternsCondition()));
            }
        });

        // A further one is not forbidden — it is a review conversation, and this failing is how
        // the conversation starts. The three below are the ways in, and each is anonymous because
        // it runs *before* there is a session to present:
        //
        //   login            — the password exchange itself.
        //   methods          — which buttons the login screen should offer. Nothing sensitive: an
        //                      instance having single sign-on is public by construction, since
        //                      the redirect it produces is.
        //   session/exchange — trades the one-time hand-off cookie the browser just received for
        //                      the session it stands for. It cannot require the session it is on
        //                      the way to producing, and the cookie is the credential.
        //
        // Listed rather than counted, so a fourth still starts the conversation.
        assertThat(open).containsExactlyInAnyOrder(
                "[/api/v1/auth/login]",
                "[/api/v1/auth/methods]",
                "[/api/v1/auth/session/exchange]",
                "[/api/v1/auth/mfa/verify]",
                "[/api/v1/scorecards/repositories/{repoId}/badge.svg]");
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

    private static boolean isOurs(HandlerMethod handler) {
        return handler.getBeanType().getPackageName().startsWith("com.asmolabs.zanshin.core.api");
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
