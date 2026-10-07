package com.asmolabs.vectispire.core.api;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * {@code t_integration} as a test found it, put back when it is done.
 *
 * <p>The table is not emptied between tests ({@code TableEmptyingTest}): its rows are V83's seed, and emptied every
 * integration would read disabled. A test that switches one remembers the rows first and restores them after, so that
 * the next test — in this class or another sharing the database — reads what the migration wrote. Switching through
 * {@code Integrations.switchTo} rather than through the governor's route, where the route is not what is tested,
 * keeps the audit chain and the outbox out of the case.
 */
final class IntegrationRows {

    private final JdbcTemplate jdbc;
    private final List<Map<String, Object>> found;

    private IntegrationRows(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
        this.found = jdbc.queryForList("select integration_key, enabled, updated_at, updated_by from t_integration");
    }

    static IntegrationRows remember(JdbcTemplate jdbc) {
        return new IntegrationRows(jdbc);
    }

    void putBack() {
        jdbc.update("delete from t_integration");
        for (Map<String, Object> row : found) {
            jdbc.update("insert into t_integration (integration_key, enabled, updated_at, updated_by) values (?, ?, ?, ?)",
                    row.get("integration_key"), row.get("enabled"), row.get("updated_at"), row.get("updated_by"));
        }
    }
}
