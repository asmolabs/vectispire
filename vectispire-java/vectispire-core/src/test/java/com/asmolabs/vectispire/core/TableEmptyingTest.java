package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Every table of the migrated schema is emptied between two tests, or left with a reason.
 *
 * <p>{@link VectispireContextTest#TABLES_CHILDREN_FIRST} is a list written by hand, and a table a migration
 * adds was missing from it until a test of its own met the previous test's rows: the licence policy, a
 * singleton row, kept whatever policy a case had stored, and a case refusing unknown licences refused them
 * in every class run after it — the tallies' suite reset it by hand before and after each case. This test
 * reads the schema itself, so that the next table is found the day its migration is written.
 *
 * <p>A table counts as emptied when it is listed, or when each of its rows goes with a row of an emptied
 * table: a foreign key {@code on delete cascade} whose columns are all {@code not null}. A nullable one
 * would leave the rows that name no parent behind, so it does not count.
 */
class TableEmptyingTest extends VectispireContextTest {

    /** Left alone on purpose, each with its reason; a line naming a table the schema lacks fails too. */
    private static final Map<String, String> KEPT = Map.of(
            "flyway_schema_history", "Flyway's own record: emptied, the next context would migrate again onto "
                    + "tables that already exist",
            "t_audit_chain_head", "the one row the migration seeds and every audit entry locks to chain onto the "
                    + "log's head: emptied, no audit entry could be written (AuditLogService refuses without it)");

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("every table of the schema is emptied between tests, listed or cascaded from one, or kept with a reason")
    void everyTableIsEmptiedOrKept() {
        Set<String> tables = new TreeSet<>(jdbc.queryForList("select table_name from information_schema.tables"
                + " where table_schema = database() and table_type = 'BASE TABLE'", String.class).stream()
                .map(name -> name.toLowerCase(Locale.ROOT)).toList());
        List<String> listed = VectispireContextTest.TABLES_CHILDREN_FIRST;

        assertThat(listed).as("listed twice").doesNotHaveDuplicates();
        assertThat(tables).as("every listed table exists").containsAll(listed);
        assertThat(tables).as("every kept table exists").containsAll(KEPT.keySet());
        assertThat(listed).as("a table is either emptied or kept").doesNotContainAnyElementsOf(KEPT.keySet());

        Set<String> emptied = new HashSet<>(listed);
        Map<String, Set<String>> cascades = cascadingParents();
        boolean grew = true;
        while (grew) {
            grew = false;
            for (Map.Entry<String, Set<String>> child : cascades.entrySet()) {
                if (!emptied.contains(child.getKey()) && child.getValue().stream().anyMatch(emptied::contains)) {
                    emptied.add(child.getKey());
                    grew = true;
                }
            }
        }

        Set<String> missed = new TreeSet<>(tables);
        missed.removeAll(emptied);
        missed.removeAll(KEPT.keySet());
        assertThat(missed)
                .as("tables neither listed in VectispireContextTest.TABLES_CHILDREN_FIRST, nor emptied by a "
                        + "not-null cascading foreign key from one listed, nor kept here with a reason")
                .isEmpty();
    }

    /**
     * The rule's halves on the schema as it is: a challenge goes with its account (a {@code not null}
     * key, {@code on delete cascade}); a gate verdict's two keys are nullable — a row naming neither would
     * survive both cascades, so the verdicts have to be listed; and a project's key to its solution is
     * {@code not null} but {@code on delete restrict}, which empties nothing.
     */
    @Test
    @DisplayName("a foreign key counts only when it cascades, through not-null columns")
    void onlyNotNullCascadesCount() {
        Map<String, Set<String>> cascades = cascadingParents();
        assertThat(cascades).containsEntry("t_mfa_challenge", Set.of("t_user"));
        assertThat(cascades).doesNotContainKey("t_gate_verdict");
        assertThat(cascades).doesNotContainKey("t_project");
    }

    /**
     * Each table's parents through a foreign key that deletes its rows with theirs and whose columns are all
     * {@code not null}: what is emptied with the parent, whatever the rows hold.
     */
    private Map<String, Set<String>> cascadingParents() {
        Map<String, Set<String>> parents = new HashMap<>();
        jdbc.query("select rc.table_name, rc.referenced_table_name,"
                + " sum(case when c.is_nullable = 'YES' then 1 else 0 end) as nullable_columns"
                + " from information_schema.referential_constraints rc"
                + " join information_schema.key_column_usage k on k.constraint_schema = rc.constraint_schema"
                + "  and k.constraint_name = rc.constraint_name and k.table_name = rc.table_name"
                + " join information_schema.columns c on c.table_schema = k.table_schema"
                + "  and c.table_name = k.table_name and c.column_name = k.column_name"
                + " where rc.constraint_schema = database() and rc.delete_rule = 'CASCADE'"
                + " group by rc.constraint_name, rc.table_name, rc.referenced_table_name", row -> {
                    if (row.getInt("nullable_columns") == 0) {
                        parents.computeIfAbsent(row.getString("table_name").toLowerCase(Locale.ROOT), any -> new HashSet<>())
                                .add(row.getString("referenced_table_name").toLowerCase(Locale.ROOT));
                    }
                });
        return parents;
    }
}
