package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
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
    @DisplayName("a visible row comes back")
    void aVisibleRowIsReturned() {
        assertThat(RowVisibility.requireVisible(Optional.of("row"), SEVEN, Visibility.everything())).isEqualTo("row");
    }
}
