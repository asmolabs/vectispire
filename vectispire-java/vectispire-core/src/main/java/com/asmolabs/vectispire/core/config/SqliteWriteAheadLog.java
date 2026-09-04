package com.asmolabs.vectispire.core.config;

import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Lets a reader read while a writer writes, which SQLite does not do by default.
 *
 * <p><b>Mesuré, et non supposé.</b> Une seule session de la suite navigateur a produit
 * <b>1015</b> {@code SQLITE_BUSY}, le premier neuf secondes après le démarrage. Chacun sort en
 * {@code 500} : une connexion refusée, un triage perdu, un écran qui dit « échec » sans raison
 * lisible. Ce n'est pas une fragilité de test — la suite ne fait qu'exposer ce qu'une deuxième
 * personne devant l'application déclencherait sur le déploiement en fichier unique.
 *
 * <p><b>La cause est le mode de journal.</b> En {@code delete}, le mode par défaut, une écriture
 * prend un verrou exclusif sur tout le fichier : toute lecture concurrente attend, et au-delà du
 * délai d'attente elle échoue. En {@code WAL}, les lectures continuent pendant l'écriture, ce qui
 * supprime la quasi-totalité de ces collisions.
 *
 * <p><b>Une fois, et non par connexion.</b> Le mode de journal est une propriété <em>du fichier</em>
 * : posé une fois, il survit aux redémarrages. C'est pour cela qu'il n'est pas dans le
 * {@code connectionInitSql} de {@link SqliteForeignKeys} — et c'est aussi bien, parce que ce slot
 * ne peut porter qu'une instruction : {@code sqlite-jdbc} n'exécute que la première d'un
 * {@code execute} multi-instructions, silencieusement. Deux pragmas séparés par un point-virgule
 * y auraient laissé le second sans effet, en donnant l'impression du contraire.
 *
 * <p><b>Après le démarrage, et non pendant.</b> Poser le pragma au moment où la source de données
 * est construite ouvrirait la première connexion trop tôt, avant que Flyway n'ait migré.
 */
@Component
class SqliteWriteAheadLog {

    private static final Logger log = LoggerFactory.getLogger(SqliteWriteAheadLog.class);
    private static final String SQLITE = "jdbc:sqlite";

    private final DataSource dataSource;

    SqliteWriteAheadLog(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @EventListener(ApplicationReadyEvent.class)
    void enable() {
        if (!(dataSource instanceof HikariDataSource pool)
                || pool.getJdbcUrl() == null
                || !pool.getJdbcUrl().startsWith(SQLITE)) {
            return;
        }

        try (Connection connection = pool.getConnection();
             Statement statement = connection.createStatement()) {
            // Le pragma répond par le mode retenu, et c'est la seule preuve qu'il a pris : sur un
            // fichier en lecture seule, ou sur un montage réseau, SQLite refuse WAL et reste en
            // `delete` sans lever d'erreur.
            var result = statement.executeQuery("PRAGMA journal_mode = WAL");
            String mode = result.next() ? result.getString(1) : "inconnu";
            if ("wal".equalsIgnoreCase(mode)) {
                log.info("SQLite: journal en WAL, les lectures ne bloquent plus derrière une écriture.");
            } else {
                log.warn("SQLite: WAL refusé, le journal reste en '{}' — les écritures concurrentes "
                        + "continueront de produire des SQLITE_BUSY.", mode);
            }
        } catch (SQLException failure) {
            log.warn("SQLite: impossible de passer le journal en WAL.", failure);
        }
    }
}
