package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.api.security.OpenToAnonymous;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.api.security.RequiresAgentKey;
import com.asmolabs.vectispire.core.api.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import java.lang.annotation.Annotation;
import java.util.List;
import java.util.stream.Collectors;

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
            RequiresSecurityLead.class,
            RequiresGovernanceRead.class,
            RequiresAccount.class,
            RequiresAgentKey.class,
            OpenToAnonymous.class);

    /**
     * The markers that answer "who", as opposed to {@link RequiresAccount}, which answers only
     * "somebody signed in" and therefore says nothing about which targets they may see.
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

    private AuthorizationMarkers() {}
}
