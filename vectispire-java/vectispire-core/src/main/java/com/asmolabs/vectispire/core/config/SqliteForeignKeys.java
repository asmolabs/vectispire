package com.asmolabs.vectispire.core.config;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

/**
 * Turns on the foreign keys SQLite has been declaring and not enforcing.
 *
 * <p><b>SQLite records an {@code on delete cascade} and then ignores it</b>, on every connection
 * that has not issued {@code PRAGMA foreign_keys = ON}. Nothing here issued it, so on the fixture
 * engine — and on any deployment running the single-file variant — the cascades in the schema were
 * decoration. It was measured rather than assumed: deleting a team left its {@code t_team_webhook}
 * row behind, a bearer capability outliving its owner in a table no screen shows.
 *
 * <p>The pragma is <b>per connection</b>, which is why this is a pool setting and not a migration:
 * a migration runs once, and the connection it ran on is not the one serving requests. Hikari's
 * init SQL runs on each connection as it is opened, which is exactly the granularity the pragma
 * needs.
 *
 * <p><b>Applied only to SQLite</b>, by reading the URL the pool was configured with. {@code PRAGMA}
 * is a syntax error on MySQL and PostgreSQL, and an init statement that fails takes every
 * connection in the pool with it — so the narrowness of this test is load-bearing, not tidiness.
 * Those two engines need nothing: PostgreSQL enforces the inline declaration as written, and MySQL
 * discards it entirely, which is what V19 repairs with real constraints.
 */
@Component
class SqliteForeignKeys implements BeanPostProcessor {

    private static final String SQLITE = "jdbc:sqlite";

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        // Set before the pool opens its first connection: Hikari reads this when it does, and the
        // bean is not yet in use at this point in its lifecycle.
        if (bean instanceof HikariDataSource pool
                && pool.getJdbcUrl() != null
                && pool.getJdbcUrl().startsWith(SQLITE)) {
            pool.setConnectionInitSql("PRAGMA foreign_keys = ON");
        }
        return bean;
    }
}
