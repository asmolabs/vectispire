package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.compliance.ComplianceControl;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.core.config.MigrationDialect;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * V92 renumbers the CRA's stored control codes to the adopted Regulation (decision 0046).
 *
 * <p>A declaration is matched to its control by code, so one left under a 2022 code is read as a control
 * this build does not carry and dropped: the statement of applicability shows the control undeclared,
 * and the organisation's decision is gone from the document with nothing said. Invisible on the fresh
 * databases every other suite starts from — there is no declaration to rewrite. So this builds the
 * schema up to V91, stores declarations as 0.11 wrote them, applies the rest, and reads them back.
 *
 * <p>Flyway alone, with the application's locations and placeholders for the engine, as
 * {@code ScoreFormulaChangedOnIntegrationTest} does.
 */
@DisplayName("the CRA's control codes, renumbered at the upgrade")
class CraControlCodesIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    @BeforeAll
    static void start() {
        CONTAINER.start();
    }

    @AfterAll
    static void stop() {
        CONTAINER.stop();
    }

    @Test
    @DisplayName("every stored CRA declaration lands on a code the catalogue carries; other frameworks' are untouched")
    void declarationsFollowTheCatalogue() throws Exception {
        flyway(null).clean();
        flyway("91").migrate();
        try (Connection connection = connect()) {
            declare(connection, "EU_CRA", "CRA-ART11-NOTIF");
            declare(connection, "EU_CRA", "CRA-ART10-SBOM");
            declare(connection, "EU_CRA", "CRA-ART10-LIFECYCLE");
            declare(connection, "EU_CRA", "CRA-ART10-VULN");
            // DORA has an Art. 11 of its own; only the CRA's codes move.
            declare(connection, "DORA", "DORA-ART11-THIRD");
        }
        flyway(null).migrate();
        try (Connection connection = connect()) {
            Map<String, String> stored = declarations(connection);
            assertThat(stored).containsExactlyInAnyOrderEntriesOf(Map.of(
                    "EU_CRA/CRA-ART14-NOTIF", "CRA-ART11-NOTIF",
                    "EU_CRA/CRA-ANNEX1-SBOM", "CRA-ART10-SBOM",
                    "EU_CRA/CRA-ART13-LIFECYCLE", "CRA-ART10-LIFECYCLE",
                    "EU_CRA/CRA-ANNEX1-VULN", "CRA-ART10-VULN",
                    "DORA/DORA-ART11-THIRD", "DORA-ART11-THIRD"));
            // And they are the codes the reconciliation looks for: a mistyped target in the migration
            // would pass the map above only if the test carried the same typo, so check the catalogue.
            assertThat(ComplianceFramework.EU_CRA.getControls().stream().map(ComplianceControl::id))
                    .containsExactlyInAnyOrderElementsOf(stored.keySet().stream()
                            .filter(key -> key.startsWith("EU_CRA/"))
                            .map(key -> key.substring("EU_CRA/".length()))
                            .toList());
        }
    }

    /** Each row's framework and code, mapped to the owner it was written with — its code before V92. */
    private static Map<String, String> declarations(Connection connection) throws SQLException {
        Map<String, String> rows = new HashMap<>();
        try (PreparedStatement statement =
                        connection.prepareStatement("select framework, control_id, control_owner from t_control_declaration");
                ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                rows.put(result.getString(1) + "/" + result.getString(2), result.getString(3));
            }
        }
        return rows;
    }

    private static void declare(Connection connection, String framework, String control) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "insert into t_control_declaration (id, framework, control_id, applicability, implementation,"
                        + " evidence_source, control_owner, decided_by, decided_at)"
                        + " values (?, ?, ?, 'APPLICABLE', 'IMPLEMENTED', 'VECTISPIRE', ?, 'admin', ?)")) {
            statement.setString(1, UUID.randomUUID().toString());
            statement.setString(2, framework);
            statement.setString(3, control);
            statement.setString(4, control);
            statement.setTimestamp(5, Timestamp.from(Instant.now()));
            statement.executeUpdate();
        }
    }

    private static Flyway flyway(String target) {
        MigrationDialect dialect = switch (ENGINE) {
            case POSTGRES -> MigrationDialect.POSTGRESQL;
            case MYSQL -> MigrationDialect.MYSQL;
        };
        var configuration = Flyway.configure()
                .locations(dialect.locations().toArray(String[]::new))
                .placeholders(dialect.placeholders())
                .cleanDisabled(false);
        configuration.dataSource(CONTAINER.getJdbcUrl(), CONTAINER.getUsername(), CONTAINER.getPassword());
        if (target != null) {
            configuration.target(target);
        }
        return configuration.load();
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(CONTAINER.getJdbcUrl(), CONTAINER.getUsername(), CONTAINER.getPassword());
    }
}
