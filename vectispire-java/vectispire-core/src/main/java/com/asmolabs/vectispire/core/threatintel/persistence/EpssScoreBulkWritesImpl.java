package com.asmolabs.vectispire.core.threatintel.persistence;

import com.asmolabs.vectispire.common.domain.threatintel.EpssFile;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import org.hibernate.Session;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@link EpssScoreBulkWrites}, over the transaction's own connection.
 *
 * <p>The name is load-bearing: Spring Data finds this class because it is the fragment interface
 * plus {@code Impl}. Renaming either half leaves {@link EpssScoreRepository} unimplementable at
 * startup.
 */
public class EpssScoreBulkWritesImpl implements EpssScoreBulkWrites {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    @Transactional
    public void insertAll(long generation, List<EpssFile.Score> scores) {
        if (scores.isEmpty()) {
            return;
        }
        // The connection the transaction holds, so the rows commit — or roll back — with it.
        entityManager.unwrap(Session.class).doWork(connection -> {
            int full = scores.size() / ROWS_PER_STATEMENT * ROWS_PER_STATEMENT;
            if (full > 0) {
                try (PreparedStatement statement = prepare(connection, ROWS_PER_STATEMENT)) {
                    for (int from = 0; from < full; from += ROWS_PER_STATEMENT) {
                        bind(statement, generation, scores.subList(from, from + ROWS_PER_STATEMENT));
                        statement.executeUpdate();
                    }
                }
            }
            if (full < scores.size()) {
                List<EpssFile.Score> rest = scores.subList(full, scores.size());
                try (PreparedStatement statement = prepare(connection, rest.size())) {
                    bind(statement, generation, rest);
                    statement.executeUpdate();
                }
            }
        });
    }

    private static PreparedStatement prepare(Connection connection, int rows) throws SQLException {
        StringBuilder sql = new StringBuilder("insert into t_epss_score (generation, cve_id, score, percentile) values ");
        for (int row = 0; row < rows; row++) {
            sql.append(row == 0 ? "(?, ?, ?, ?)" : ", (?, ?, ?, ?)");
        }
        return connection.prepareStatement(sql.toString());
    }

    private static void bind(PreparedStatement statement, long generation, List<EpssFile.Score> rows)
            throws SQLException {
        int parameter = 1;
        for (EpssFile.Score row : rows) {
            statement.setLong(parameter++, generation);
            statement.setString(parameter++, row.cve());
            statement.setDouble(parameter++, row.score());
            statement.setDouble(parameter++, row.percentile());
        }
    }
}
