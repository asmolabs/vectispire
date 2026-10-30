package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireContextTest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The scan history's order has an index to be read from (V97).
 *
 * <p><b>The defect this closes.</b> {@code GET /api/v1/scans} and the dashboard's recent scans read
 * {@code t_scan} newest first with a limit — {@code order by created_at desc, id desc} — and no index
 * led with that order: MySQL sorted the whole table, and its filesort carries the selected columns, the
 * SBOM among them, since the history reads entities. 480 to 580 ms a call on the 1.0.0-rc.1 load test's
 * estate (900 scans of 340 KB), growing with every scan kept; 5 ms once the index exists, walked backwards
 * and stopped after the page.
 *
 * <p><b>Why the index and not the plan is asserted.</b> MySQL chooses the index by the table's size, SBOM
 * pages included: on a test table of a few thousand small rows it sorts — measured, with the index
 * present — since the sort is cheap there, and a plan asserted here would pin the optimizer's arithmetic
 * rather than the schema. The load test ({@code load/}) measured the plan on an estate; this keeps the
 * index it needs from being dropped or reordered.
 */
@DisplayName("the scan history's order")
class ScanHistoryIndexDatabaseTest extends VectispireContextTest {

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("is an index's leading columns, in the order the history reads")
    void theHistoryHasItsIndex() {
        Map<String, List<String>> indexes = new LinkedHashMap<>();
        jdbc.query("""
                select index_name, column_name from information_schema.statistics
                 where table_schema = database() and table_name = 't_scan'
                 order by index_name, seq_in_index""",
                row -> {
                    indexes.computeIfAbsent(row.getString(1), ignored -> new ArrayList<>())
                            .add(row.getString(2).toLowerCase(Locale.ROOT));
                });

        assertThat(indexes.values())
                .as("an index of t_scan led by (created_at, id): without it every page of the history sorts the "
                        + "table, SBOMs included — " + indexes)
                .anySatisfy(columns -> assertThat(columns).startsWith("created_at", "id"));
    }
}
