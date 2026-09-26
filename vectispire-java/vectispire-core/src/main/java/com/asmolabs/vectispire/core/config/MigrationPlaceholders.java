package com.asmolabs.vectispire.core.config;

import java.sql.DatabaseMetaData;
import java.util.HashMap;
import java.util.Map;
import javax.sql.DataSource;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.springframework.boot.flyway.autoconfigure.FlywayConfigurationCustomizer;
import org.springframework.boot.jdbc.DatabaseDriver;
import org.springframework.jdbc.support.JdbcUtils;
import org.springframework.jdbc.support.MetaDataAccessException;
import org.springframework.stereotype.Component;

/**
 * Hands Flyway the type placeholders of the engine it is about to migrate (decision 0027).
 *
 * <p><b>The engine is identified the way Spring Boot identifies it for {@code {vendor}}</b>: the
 * URL the data source reports, through {@link DatabaseDriver}. Asking any other way — a property,
 * the Hibernate dialect — would be a second answer to "which engine is this", and the day they
 * disagreed the MySQL directory would be read with PostgreSQL's types.
 *
 * <p><b>An engine without a mapping stops the application.</b> Spring Boot leaves
 * {@code {vendor}} unresolved for a driver it does not know, and Flyway would then find no
 * migration and report an empty, "up to date" schema; failing here says why instead.
 *
 * <p><b>A {@code spring.flyway.placeholders.*} property cannot redefine a type.</b> Overriding
 * {@code ts} with {@code datetime} would truncate the audit chain's timestamps on MySQL — the
 * exact defect decision 0013 exists to prevent — through a setting nobody reviews as schema.
 * Other placeholders pass through untouched.
 */
@Component
class MigrationPlaceholders implements FlywayConfigurationCustomizer {

    @Override
    public void customize(FluentConfiguration configuration) {
        MigrationDialect dialect = dialectOf(configuration.getDataSource());

        Map<String, String> placeholders = new HashMap<>(configuration.getPlaceholders());
        dialect.placeholders().forEach((name, value) -> {
            String configured = placeholders.put(name, value);
            if (configured != null && !configured.equals(value)) {
                throw new IllegalStateException(
                        "spring.flyway.placeholders." + name + " is set to \"" + configured
                                + "\", but that placeholder is a column type Vectispire fixes per"
                                + " engine (\"" + value + "\" on " + dialect.vendor() + "). Remove"
                                + " the property: see decision 0027.");
            }
        });
        configuration.placeholders(placeholders);
    }

    static MigrationDialect dialectOf(DataSource dataSource) {
        String url;
        try {
            url = JdbcUtils.extractDatabaseMetaData(dataSource, DatabaseMetaData::getURL);
        } catch (MetaDataAccessException unreachable) {
            throw new IllegalStateException("Cannot read the database URL to choose migrations", unreachable);
        }
        // The URL is not quoted in the message below: a JDBC URL may carry the password.
        String vendor = DatabaseDriver.fromJdbcUrl(url).getId();
        return MigrationDialect.ofVendor(vendor).orElseThrow(() -> new IllegalStateException(
                "No migrations exist for the database engine \"" + vendor + "\"."
                        + " Vectispire runs on MySQL and PostgreSQL; see decision 0014."));
    }
}
