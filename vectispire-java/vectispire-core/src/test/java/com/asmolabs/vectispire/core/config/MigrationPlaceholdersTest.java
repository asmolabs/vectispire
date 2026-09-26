package com.asmolabs.vectispire.core.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.util.Map;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@DisplayName("the migration placeholders are chosen by the engine Flyway migrates")
class MigrationPlaceholdersTest {

    @TempDir
    Path scratch;

    private DataSource sqlite() {
        return new DriverManagerDataSource("jdbc:sqlite:" + scratch.resolve("placeholders.db"));
    }

    private static DataSource reporting(String url) throws Exception {
        DataSource dataSource = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        DatabaseMetaData metadata = mock(DatabaseMetaData.class);
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.getMetaData()).thenReturn(metadata);
        when(metadata.getURL()).thenReturn(url);
        return dataSource;
    }

    @Test
    @DisplayName("each URL gets its engine's types, by the id Spring Boot resolves {vendor} to")
    void eachEngineGetsItsTypes() throws Exception {
        assertThat(MigrationPlaceholders.dialectOf(reporting("jdbc:mysql://db:3306/vectispire")))
                .isEqualTo(MigrationDialect.MYSQL);
        assertThat(MigrationPlaceholders.dialectOf(reporting("jdbc:postgresql://db:5432/vectispire")))
                .isEqualTo(MigrationDialect.POSTGRESQL);
        assertThat(MigrationPlaceholders.dialectOf(sqlite())).isEqualTo(MigrationDialect.SQLITE);
    }

    @Test
    @DisplayName("the placeholders reach Flyway's configuration, next to any other placeholder")
    void thePlaceholdersReachFlyway() {
        FluentConfiguration configuration = Flyway.configure()
                .dataSource(sqlite())
                .placeholders(Map.of("tenant", "acme"));

        new MigrationPlaceholders().customize(configuration);

        assertThat(configuration.getPlaceholders())
                .containsAllEntriesOf(MigrationDialect.SQLITE.placeholders())
                .containsEntry("tenant", "acme");
    }

    @Test
    @DisplayName("a property cannot redefine a column type")
    void aPropertyCannotRedefineAType() throws Exception {
        // `ts` overridden to a bare `datetime` is the truncation decision 0013 exists to prevent,
        // arriving through a setting nobody reviews as schema.
        FluentConfiguration configuration = Flyway.configure()
                .dataSource(reporting("jdbc:mysql://db:3306/vectispire"))
                .placeholders(Map.of("ts", "datetime"));

        assertThatThrownBy(() -> new MigrationPlaceholders().customize(configuration))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.flyway.placeholders.ts");
    }

    @Test
    @DisplayName("an engine without migrations stops the start, without quoting the URL")
    void anUnknownEngineStops() throws Exception {
        assertThatThrownBy(() -> MigrationPlaceholders.dialectOf(
                        reporting("jdbc:h2:mem:vectispire;PASSWORD=hunter2")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("\"h2\"")
                .hasMessageNotContaining("hunter2");
    }
}
