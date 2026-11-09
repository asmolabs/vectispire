package com.asmolabs.vectispire.common.domain.paging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("batches of a lookup")
class BatchesTest {

    @Test
    @DisplayName("splits a lookup into batches, the last one short, and nothing into nothing")
    void splitsIntoBatches() {
        List<Integer> items = IntStream.range(0, 200).boxed().toList();

        List<List<Integer>> batches = Batches.of(items, 90);

        assertThat(batches).hasSize(3);
        assertThat(batches.get(0)).hasSize(90);
        assertThat(batches.get(2)).hasSize(20);
        assertThat(batches.stream().flatMap(List::stream).toList()).isEqualTo(items);
        assertThat(Batches.of(List.of(), 90)).isEmpty();
    }

    @Test
    @DisplayName("a list of exactly one batch is one batch, and one item more is two")
    void theBoundary() {
        List<Integer> thousand = IntStream.range(0, 1_000).boxed().toList();
        List<Integer> oneMore = IntStream.range(0, 1_001).boxed().toList();

        assertThat(Batches.of(thousand, 1_000)).hasSize(1);
        assertThat(Batches.of(oneMore, 1_000)).hasSize(2).last().isEqualTo(List.of(1_000));
    }

    @Test
    @DisplayName("passes a null item through, as the loops it replaced did")
    void nullsPassThrough() {
        assertThat(Batches.of(Arrays.asList(1L, null, 3L), 2)).containsExactly(Arrays.asList(1L, null), List.of(3L));
    }

    @Test
    @DisplayName("refuses a batch of nothing, which would never end")
    void refusesAnEmptyBatch() {
        assertThatThrownBy(() -> Batches.of(List.of(1), 0)).isInstanceOf(IllegalArgumentException.class);
    }
}
