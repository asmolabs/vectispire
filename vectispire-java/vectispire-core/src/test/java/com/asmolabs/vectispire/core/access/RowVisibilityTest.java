package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a target refused by its identifier")
class RowVisibilityTest {

    private static final ScanTarget SEVEN = new ScanTarget.Repository(7L);
    private static final Visibility ONLY_EIGHT = Visibility.only(List.of(new ScanTarget.Repository(8L)));

    @Test
    @DisplayName("absent and hidden are one refusal, word for word")
    void absentAndHiddenAreIndistinguishable() {
        Throwable absent = catchThrowable(() -> RowVisibility.requireVisible(Optional.empty(), SEVEN, Visibility.everything()));
        Throwable hidden = catchThrowable(() -> RowVisibility.requireVisible(Optional.of("row"), SEVEN, ONLY_EIGHT));

        assertThat(absent).isInstanceOf(NoSuchElementException.class);
        assertThat(hidden).isInstanceOf(NoSuchElementException.class);
        assertThat(absent.getMessage()).isEqualTo(hidden.getMessage());
        // And the same sentence as a target refused before anything is loaded.
        assertThatThrownBy(() -> RowVisibility.requireVisible(SEVEN, ONLY_EIGHT)).hasMessage(absent.getMessage());
    }

    @Test
    @DisplayName("a permitted target comes back as the proof a service takes, naming that target")
    void aPermittedTargetIsProven() {
        ScanTarget.Repository eight = new ScanTarget.Repository(8L);
        assertThat(RowVisibility.requireVisible(eight, ONLY_EIGHT).target()).isEqualTo(eight);
    }

    @Test
    @DisplayName("a visible row comes back")
    void aVisibleRowIsReturned() {
        assertThat(RowVisibility.requireVisible(Optional.of("row"), SEVEN, Visibility.everything())).isEqualTo("row");
    }

    @Test
    @DisplayName("a project is seen whole or not at all: everything, granted as such, or every one of its repositories")
    void aProjectIsSeenWhole() {
        List<Long> members = List.of(7L, 8L);
        Visibility both = Visibility.only(List.of(SEVEN, new ScanTarget.Repository(8L)));

        assertThat(RowVisibility.requireWhollyVisibleProject(3, Optional.of("Checkout"), members,
                new VisibilityService.Allowance(Visibility.everything(), Set.of())).name()).isEqualTo("Checkout");
        assertThat(RowVisibility.requireWhollyVisibleProject(3, Optional.of("Checkout"), members,
                new VisibilityService.Allowance(both, Set.of())).projectId()).isEqualTo(3);
        assertThat(RowVisibility.requireWhollyVisibleProject(3, Optional.of("Empty"), List.of(),
                new VisibilityService.Allowance(Visibility.only(List.of()), Set.of(3L))).name()).isEqualTo("Empty");

        Throwable absent = catchThrowable(() -> RowVisibility.requireWhollyVisibleProject(3, Optional.empty(), List.of(),
                new VisibilityService.Allowance(Visibility.everything(), Set.of())));
        assertThat(absent).hasMessage("Project not found.");
        // Part of it, none of it, and every one of none: refused in the words of an absent project.
        assertThatThrownBy(() -> RowVisibility.requireWhollyVisibleProject(3, Optional.of("Checkout"), members,
                new VisibilityService.Allowance(ONLY_EIGHT, Set.of()))).hasMessage(absent.getMessage());
        assertThatThrownBy(() -> RowVisibility.requireWhollyVisibleProject(3, Optional.of("Checkout"), members,
                new VisibilityService.Allowance(Visibility.only(List.of()), Set.of()))).hasMessage(absent.getMessage());
        assertThatThrownBy(() -> RowVisibility.requireWhollyVisibleProject(3, Optional.of("Empty"), List.of(),
                new VisibilityService.Allowance(ONLY_EIGHT, Set.of(4L)))).hasMessage(absent.getMessage());
    }
}
