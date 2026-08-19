package com.asmolabs.zanshin.common.domain.access;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("who is allowed to see which targets")
class VisibilityTest {

    private static final ScanTarget ONE = new ScanTarget.Repository(1);
    private static final ScanTarget TWO = new ScanTarget.Repository(2);
    private static final ScanTarget IMAGE = new ScanTarget.Container(1);

    @Test
    @DisplayName("a repository and a container with the same number are not the same target")
    void theKindIsPartOfTheIdentity() {
        Visibility visibility = Visibility.only(List.of(ONE));

        // The obvious near-miss: filtering on the number alone would show every image whose id
        // matches a repository somebody was assigned.
        assertThat(visibility.permits(ONE)).isTrue();
        assertThat(visibility.permits(IMAGE)).isFalse();
    }

    @Test
    @DisplayName("an unassigned account sees nothing, not everything")
    void anEmptySetIsARestrictionAndNotItsAbsence() {
        Visibility none = Visibility.only(List.of());

        assertThat(none.permits(ONE)).isFalse();
        assertThat(none.isEmpty()).isTrue();
        // The distinction the whole type exists for: a filter of "no targets" is still a filter.
        assertThat(none.asFilter()).contains(Set.of());
    }

    @Test
    void unrestrictedPermitsAnythingAndFiltersNothing() {
        assertThat(Visibility.everything().permits(ONE)).isTrue();
        assertThat(Visibility.everything().asFilter()).isEmpty();
        assertThat(Visibility.everything().isEmpty()).isFalse();
    }

    @Test
    @DisplayName("two restrictions meet at their intersection, never their union")
    void narrowingIsAnIntersection() {
        Visibility key = Visibility.only(List.of(ONE));
        Visibility account = Visibility.only(List.of(ONE, TWO));

        // A narrow key held by a broad account stays narrow. The union would let the key widen
        // itself by whoever happens to be carrying it.
        assertThat(key.and(account).asFilter()).contains(Set.of(ONE));
        assertThat(account.and(key).asFilter()).contains(Set.of(ONE));
    }

    @Test
    @DisplayName("narrowing against no restriction keeps the restriction")
    void unrestrictedNarrowsToTheOther() {
        Visibility only = Visibility.only(List.of(ONE));

        assertThat(Visibility.everything().and(only).asFilter()).contains(Set.of(ONE));
        assertThat(only.and(Visibility.everything()).asFilter()).contains(Set.of(ONE));
    }

    @Test
    @DisplayName("two disjoint restrictions leave nothing")
    void disjointRestrictionsSeeNothing() {
        assertThat(Visibility.only(List.of(ONE)).and(Visibility.only(List.of(TWO))).isEmpty()).isTrue();
    }

    @Test
    void nothingPermitsANullTarget() {
        assertThat(Visibility.only(List.of(ONE)).permits(null)).isFalse();
    }
}
