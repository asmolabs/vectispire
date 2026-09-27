package com.asmolabs.vectispire.common.domain.enrichment;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("enrichment catalogs")
class CatalogsTest {

    @Test
    @DisplayName("splits a lookup into batches, the last one short, and nothing into nothing")
    void splitsIntoBatches() {
        List<Integer> items = IntStream.range(0, 200).boxed().toList();

        List<List<Integer>> batches = Catalogs.batches(items, 90);

        assertThat(batches).hasSize(3);
        assertThat(batches.get(0)).hasSize(90);
        assertThat(batches.get(2)).hasSize(20);
        assertThat(batches.stream().flatMap(List::stream).toList()).isEqualTo(items);
        assertThat(Catalogs.batches(List.of(), 90)).isEmpty();
    }
}
