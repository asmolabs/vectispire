package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.web.security.OpenToAnonymous;
import com.asmolabs.vectispire.core.issues.IssueTriageService;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaCodeUnit;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * The platform governor takes no triage decision, on any route that takes one.
 *
 * <p><b>Derived, not listed.</b> The governor decides the rules — four-eyes, visibility — and the
 * separation holds only if the role that can lift a rule cannot act under it. The triage routes
 * carried {@code @RequiresWriteAccount}, which leaves the governor out; the exception review
 * carried {@code @RequiresSecurityLead}, which lets it in, and confirmed or extended exceptions for
 * a role that approves nothing. A list of "the triage routes" would have been written by whoever
 * forgot that one. The routes here are found from the code: every handler whose calls reach a
 * decision of {@link IssueTriageService}, followed through services, interfaces and lambdas.
 *
 * <p>Each is asked by a governor, and must answer 403 — and by a CISO, who must not: a refusal that
 * also turned away the roles meant to decide would pass the first half for the wrong reason.
 */
@DisplayName("the platform governor and triage decisions")
class TriageGovernorRoutesTest extends ApiTestBase {

    private static final String CORE = "com.asmolabs.vectispire.core";

    /**
     * The methods of {@link IssueTriageService} that are not a decision anybody takes, with the
     * reason. Everything else it offers writes a decision.
     */
    private static final Map<String, String> NOT_DECISIONS = Map.of(
            "expireStale", "the maintenance tick brings lapsed decisions back under review; no account decides it");

    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    private RequestMappingHandlerMapping handlerMapping;

    private record Route(HttpMethod method, String path, String handler) {}

    @Test
    @DisplayName("every route reaching a triage decision refuses the governor and admits a CISO")
    void theGovernorIsRefusedEverywhere() throws Exception {
        List<Route> routes = triageRoutes();

        // A derivation that found nothing passes for ever: pinned to routes known to decide.
        assertThat(routes).extracting(Route::handler).contains(
                "IssuesController#triage",
                "IssuesController#triageMany",
                "VexController#ingestVex",
                "ExceptionsRegisterController#review");

        String governor = tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
        String ciso = asCiso();
        List<String> failures = new ArrayList<>();
        for (Route route : routes) {
            int asGovernor = status(route, governor);
            if (asGovernor != 403) {
                failures.add("%s %s (%s) answered %d to the governor".formatted(
                        route.method(), route.path(), route.handler(), asGovernor));
            }
            int asCiso = status(route, ciso);
            if (asCiso == 403 || asCiso == 401) {
                failures.add("%s %s (%s) answered %d to a CISO — the refusal is not the governor's".formatted(
                        route.method(), route.path(), route.handler(), asCiso));
            }
        }
        assertThat(failures).isEmpty();
    }

    private int status(Route route, String token) throws Exception {
        return mvc.perform(authenticated(request(route.method(), route.path()), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andReturn().getResponse().getStatus();
    }

    /** Every route, with its path variables filled, whose handler reaches a decision. */
    private List<Route> triageRoutes() {
        JavaClasses classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages(CORE);
        Set<JavaCodeUnit> decisions = classes.get(IssueTriageService.class).getMethods().stream()
                .filter(method -> method.getModifiers().contains(JavaModifier.PUBLIC))
                .filter(method -> !NOT_DECISIONS.containsKey(method.getName()))
                .collect(Collectors.toSet());

        List<Route> routes = new ArrayList<>();
        for (Map.Entry<RequestMappingInfo, HandlerMethod> mapping : handlerMapping.getHandlerMethods().entrySet()) {
            Method handler = mapping.getValue().getMethod();
            // No account acts on an anonymous route: the tracker's webhook is authenticated by its
            // signature, and what it may settle is `TicketWebhookCannotSettleTest`'s.
            if (handler.isAnnotationPresent(OpenToAnonymous.class)) {
                continue;
            }
            if (!classes.contain(handler.getDeclaringClass())) {
                continue;
            }
            JavaMethod start = classes.get(handler.getDeclaringClass())
                    .getMethod(handler.getName(), handler.getParameterTypes());
            if (!reaches(start, decisions)) {
                continue;
            }
            String id = handler.getDeclaringClass().getSimpleName() + "#" + handler.getName();
            for (String pattern : mapping.getKey().getPatternValues()) {
                String path = pattern.replaceAll("\\{[^}]+}", "1");
                for (org.springframework.web.bind.annotation.RequestMethod method : mapping.getKey().getMethodsCondition().getMethods()) {
                    routes.add(new Route(HttpMethod.valueOf(method.name()), path, id));
                }
            }
        }
        return routes;
    }

    /** Whether any call path from {@code start}, through the application's own code, reaches a target. */
    private static boolean reaches(JavaCodeUnit start, Set<JavaCodeUnit> targets) {
        Deque<JavaCodeUnit> pending = new ArrayDeque<>(List.of(start));
        Set<JavaCodeUnit> seen = new HashSet<>();
        while (!pending.isEmpty()) {
            JavaCodeUnit unit = pending.pop();
            if (!seen.add(unit)) {
                continue;
            }
            if (targets.contains(unit)) {
                return true;
            }
            for (JavaMethodCall call : unit.getMethodCallsFromSelf()) {
                JavaClass owner = call.getTargetOwner();
                if (!owner.getPackageName().startsWith(CORE)) {
                    continue;
                }
                call.getTarget().resolveMember().ifPresent(pending::push);
                // Through an interface — a port — to every implementation of the method.
                for (JavaClass implementation : owner.getAllSubclasses()) {
                    implementation.tryGetMethod(call.getName(), names(call)).ifPresent(pending::push);
                }
            }
        }
        return false;
    }

    private static String[] names(JavaMethodCall call) {
        return call.getTarget().getRawParameterTypes().stream().map(JavaClass::getName).toArray(String[]::new);
    }
}
