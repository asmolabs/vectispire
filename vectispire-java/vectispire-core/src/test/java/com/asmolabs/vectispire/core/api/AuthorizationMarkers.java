package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.web.security.OpenToAnonymous;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.RequiresAgentKey;
import com.asmolabs.vectispire.core.access.web.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.access.web.security.RequiresPlatformGovernor;
import com.asmolabs.vectispire.core.access.web.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.access.web.security.RequiresWriteAccount;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.annotation.Annotation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * The markers a route may wear, in <b>one</b> list.
 *
 * <p><b>There were three, and adding a sixth marker found them.</b> {@code RouteAuthorizationTest}
 * held the set as annotation classes, {@code RouteScopingTest} as an alternation inside a regular
 * expression, and {@code AuthorizationCoverageTest} as a chain of {@code source.contains(…)} — and
 * the day {@link RequiresGovernanceRead} was introduced, the first was updated and the other two
 * reported every route that had just adopted it as having no guard at all.
 *
 * <p>That failure was loud, which is the good case. The quiet one is the other direction: a marker
 * dropped from one of these lists silently stops being recognised as a guard, and a test whose job
 * is to notice unguarded routes starts reporting guarded ones instead — or, worse, a list that
 * gains a marker nobody grants makes a route look guarded when it is not.
 *
 * <p>The same argument {@code Role} makes about its own flags, one layer out: the set is written
 * once, and everything that needs it derives its own shape from here.
 */
final class AuthorizationMarkers {

    /** Every marker, as annotation types. */
    static final List<Class<? extends Annotation>> ALL = List.of(
            RequiresAdministrator.class,
            RequiresPlatformGovernor.class,
            RequiresSecurityLead.class,
            RequiresGovernanceRead.class,
            RequiresWriteAccount.class,
            RequiresAccount.class,
            RequiresAgentKey.class,
            OpenToAnonymous.class);

    /**
     * The markers that answer "who", as opposed to {@link RequiresAccount}, which answers only
     * "somebody signed in" and therefore says nothing about which targets they may see.
     *
     * <p>{@link RequiresWriteAccount} belongs here: it does name who may call — everyone but a
     * read-only account. It is the widest of them, which is the point. The routes it guards are
     * ordinary work, and only the account that exists to look sits outside it.
     */
    static final List<Class<? extends Annotation>> ROLE_GUARDS = ALL.stream()
            .filter(marker -> marker != RequiresAccount.class)
            .toList();

    /**
     * {@link #ROLE_GUARDS} as a regular-expression alternation, for the rules that read source
     * text rather than reflect over handlers.
     *
     * <p>Both written forms are matched — a bare {@code @OpenToAnonymous} and a fully qualified
     * {@code @com.asmolabs.….OpenToAnonymous} — because one route uses the second and an earlier
     * draft of that rule reported it as unguarded.
     */
    static String roleGuardPattern() {
        return "@(?:[\\w.]+\\.)?(?:"
                + ROLE_GUARDS.stream().map(Class::getSimpleName).collect(Collectors.joining("|"))
                + ")\\b";
    }

    /** True when {@code source} carries any marker that names who may call the route. */
    static boolean statesARole(String source) {
        return ROLE_GUARDS.stream().anyMatch(marker -> source.contains("@" + marker.getSimpleName()));
    }

    // Declared before `SCOPE_GUARDS`, which reads them while the class initialises: static
    // fields initialise in order, and these were still null the first time round.
    private static final Pattern ANY_ROLE = Pattern.compile("^hasAnyRole\\((.*)\\)$");
    private static final Pattern QUOTED = Pattern.compile("'([A-Z_]+)'");

    /**
     * The markers that settle <b>whose data</b> a route may return, as opposed to merely who may
     * call it: those whose every admitted role sees the whole estate.
     *
     * <p><b>Derived from the markers' own {@code @PreAuthorize} and from {@link Role}</b>, never
     * listed. The scoping lints used {@link #ROLE_GUARDS}, which includes
     * {@link RequiresWriteAccount} — and that marker admits {@code SECURITY_CHAMPION} and
     * {@code USER}, the two roles whose visibility is a handful of targets. A route guarded by it
     * alone was reported as scoped while it served the whole estate to exactly the accounts the
     * scope exists for. Reading the expression means a role added to a marker, or a role losing
     * its global scope, changes this set without anybody remembering to.
     *
     * <p>A marker with no role expression — the agent key, anonymous access — is not here: it
     * names no account, so it cannot vouch for an account's scope. Such routes are exempted by
     * name, with a reason.
     */
    static final List<Class<? extends Annotation>> SCOPE_GUARDS = ALL.stream()
            .filter(AuthorizationMarkers::admitsOnlyGlobalScope)
            .toList();

    static boolean admitsOnlyGlobalScope(Class<? extends Annotation> marker) {
        PreAuthorize rule = marker.getAnnotation(PreAuthorize.class);
        if (rule == null) {
            return false;
        }
        // Only the one shape the markers use. Anything else — `isAuthenticated()`, a compound
        // expression — is not understood here, and not understood means not trusted.
        Matcher anyRole = ANY_ROLE.matcher(rule.value().trim());
        if (!anyRole.matches()) {
            return false;
        }
        List<Role> admitted = QUOTED.matcher(anyRole.group(1)).results()
                .map(match -> Role.valueOf(match.group(1)))
                .toList();
        return !admitted.isEmpty() && admitted.stream().allMatch(Role::hasGlobalSecurityScope);
    }

    /** {@link #SCOPE_GUARDS} as a regular-expression alternation, both written forms matched. */
    static String scopeGuardPattern() {
        return "@(?:[\\w.]+\\.)?(?:"
                + SCOPE_GUARDS.stream().map(Class::getSimpleName).collect(Collectors.joining("|"))
                + ")\\b";
    }

    /** The control plane's sources, relative to the module directory where Gradle runs a test. */
    private static final Path CORE_SOURCES = Path.of("src/main/java/com/asmolabs/vectispire/core");

    /**
     * Every controller source the textual lints read: under {@code core/<module>/web/}, where every
     * module keeps its own since step 5 emptied {@code core/api/} (decisions 0028 and 0029).
     *
     * <p><b>One walk for both lints, and it follows the modules.</b> Both used to walk
     * {@code core/api} alone; the first controller moved into a module would have left both rules
     * reading around it, green, while a route there served whatever it liked. A controller anywhere
     * else fails {@code ArchitectureTest.everyClassHasAPlace} before it could be missed here.
     */
    static List<Path> controllerSources() {
        try (Stream<Path> files = Files.walk(CORE_SOURCES)) {
            return files.filter(file -> file.getFileName().toString().endsWith("Controller.java"))
                    .filter(file -> {
                        Path relative = CORE_SOURCES.relativize(file);
                        return relative.getNameCount() > 2 && relative.getName(1).toString().equals("web");
                    })
                    .sorted()
                    .toList();
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }

    private AuthorizationMarkers() {}
}
