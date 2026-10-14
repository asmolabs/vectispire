package com.asmolabs.vectispire.common.domain.paging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The page a list route was asked for.
 *
 * <p>The routes that page on request keep their whole-list answer when asked nothing — that answer is in
 * the 0.11.0 contract — so the case that matters most is the empty one: no limit, no window.
 */
@DisplayName("a list window")
class ListWindowTest {

    private static final List<Integer> ROWS = IntStream.rangeClosed(1, 7).boxed().toList();

    @Test
    @DisplayName("asked nothing, is no window: the route answers its whole list")
    void absentIsTheWholeList() {
        assertThat(ListWindow.requested(null, null)).isEmpty();
    }

    @Test
    @DisplayName("cuts the rows it is given, the last page short and past it empty")
    void cutsPages() {
        assertThat(ListWindow.requested(3, null).orElseThrow().of(ROWS)).containsExactly(1, 2, 3);
        assertThat(ListWindow.requested(3, 3).orElseThrow().of(ROWS)).containsExactly(4, 5, 6);
        assertThat(ListWindow.requested(3, 6).orElseThrow().of(ROWS)).containsExactly(7);
        assertThat(ListWindow.requested(3, 9).orElseThrow().of(ROWS)).isEmpty();
        assertThat(ListWindow.requested(3, 6).orElseThrow().page()).isEqualTo(2);
    }

    @Test
    @DisplayName("refuses a limit outside 1 to 500 rather than clamping it")
    void boundsTheLimit() {
        assertThat(ListWindow.requested(ListWindow.MAX_LIMIT, null)).isPresent();
        assertThatThrownBy(() -> ListWindow.requested(ListWindow.MAX_LIMIT + 1, null))
                .isInstanceOf(InvalidInputException.class)
                .hasMessage("The limit is between 1 and 500.");
        assertThatThrownBy(() -> ListWindow.requested(0, null)).isInstanceOf(InvalidInputException.class);
    }

    @Test
    @DisplayName("refuses an offset that is negative or between two pages")
    void boundsTheOffset() {
        assertThatThrownBy(() -> ListWindow.requested(10, -10))
                .isInstanceOf(InvalidInputException.class)
                .hasMessage("The offset is zero or a multiple of the limit.");
        assertThatThrownBy(() -> ListWindow.requested(10, 5)).isInstanceOf(InvalidInputException.class);
    }

    @Test
    @DisplayName("refuses an offset without a limit, which would be everything after it")
    void anOffsetNeedsALimit() {
        assertThatThrownBy(() -> ListWindow.requested(null, 0))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("with a limit");
    }

    @Test
    @DisplayName("on a route that always pages, falls back to its default limit")
    void defaultsForRoutesThatAlwaysPage() {
        assertThat(ListWindow.of(null, null, 100)).isEqualTo(new ListWindow(100, 0));
        assertThatThrownBy(() -> ListWindow.of(1000, null, 100)).isInstanceOf(InvalidInputException.class);
    }
}
