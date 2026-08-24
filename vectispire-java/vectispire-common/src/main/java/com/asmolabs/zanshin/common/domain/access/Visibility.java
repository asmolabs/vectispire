package com.asmolabs.zanshin.common.domain.access;

import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;

/**
 * Which targets a caller is allowed to see.
 *
 * <p><b>The whole rule, in one place, and pure.</b> Authorization spread across nine controllers
 * is nine chances to forget one, and the forgotten one is the hole — a reader who cannot open
 * the repositories screen but can still export its backlog by guessing the identifier. Every
 * read path asks this object.
 *
 * <p>Two states rather than a boolean plus a nullable set, because the third combination —
 * "unrestricted but here is a set" — has no meaning and would eventually be constructed.
 */
public sealed interface Visibility {

    /** Everything. Administrators, and every account while the deployment leaves it open. */
    record Everything() implements Visibility {}

    /**
     * Only these.
     *
     * <p><b>An empty set is a legitimate value and means nothing is visible.</b> Read as "no
     * restriction" it would turn an account nobody has assigned anything to into an account that
     * sees the lot — the exact inversion this type exists to prevent, and the one a boolean
     * would have invited.
     */
    record Only(Set<ScanTarget> targets) implements Visibility {

        public Only {
            targets = Set.copyOf(targets);
        }
    }

    static Visibility everything() {
        return new Everything();
    }

    static Visibility only(Collection<ScanTarget> targets) {
        return new Only(Set.copyOf(targets));
    }

    default boolean permits(ScanTarget target) {
        return switch (this) {
            case Everything ignored -> true;
            case Only only -> target != null && only.targets().contains(target);
        };
    }

    /**
     * The targets to filter a query by, or empty when no filter applies.
     *
     * <p>{@code Optional.empty()} means "do not narrow", which is <em>not</em> the same as an
     * empty set. A repository that confused the two would answer an unassigned reader with the
     * whole backlog.
     */
    default Optional<Set<ScanTarget>> asFilter() {
        return switch (this) {
            case Everything ignored -> Optional.empty();
            case Only only -> Optional.of(only.targets());
        };
    }

    /** Whether anything at all is visible. An unassigned reader in restricted mode sees nothing. */
    default boolean isEmpty() {
        return this instanceof Only only && only.targets().isEmpty();
    }

    /**
     * Narrows to the intersection.
     *
     * <p>Used where two restrictions meet: an API key issued for one repository, presented by a
     * reader assigned to three. The answer is the one repository — <b>never the union</b>, which
     * is what an {@code ||} written in a hurry produces, and which would let a narrow key widen
     * itself by being held by a broad account.
     */
    default Visibility and(Visibility other) {
        if (this instanceof Everything) {
            return other;
        }
        if (other instanceof Everything) {
            return this;
        }
        Set<ScanTarget> mine = ((Only) this).targets();
        return Visibility.only(((Only) other).targets().stream().filter(mine::contains).toList());
    }
}
