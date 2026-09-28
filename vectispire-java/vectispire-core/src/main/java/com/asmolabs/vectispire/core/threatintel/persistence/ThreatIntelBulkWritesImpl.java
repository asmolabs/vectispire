package com.asmolabs.vectispire.core.threatintel.persistence;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.Instant;
import java.util.List;
import org.hibernate.Session;
import org.hibernate.query.MutationQuery;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@link ThreatIntelBulkWrites}, as native statements of the entity manager.
 *
 * <p><b>Through Hibernate, not the bare connection</b> as the EPSS scores are: two of these columns
 * are instants, and a timestamp bound by hand is converted in the JVM's zone by one driver and in
 * UTC by another. Bound through the entity manager, an {@link Instant} is written the way the
 * entity's own column is, and read back as it was written.
 *
 * <p>The name is load-bearing: Spring Data finds this class because it is the fragment interface
 * plus {@code Impl}. Renaming either half leaves {@link ThreatIntelRepository} unimplementable at
 * startup.
 */
public class ThreatIntelBulkWritesImpl implements ThreatIntelBulkWrites {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    @Transactional
    public void insertListed(List<Listing> listings, Instant updatedAt) {
        for (int from = 0; from < listings.size(); from += ROWS_PER_STATEMENT) {
            List<Listing> rows = listings.subList(from, Math.min(from + ROWS_PER_STATEMENT, listings.size()));
            StringBuilder sql = new StringBuilder(
                    "insert into t_threat_intel_feed (cve_id, is_kev, date_added, updated_at) values ");
            for (int row = 0; row < rows.size(); row++) {
                int first = row * 4 + 1;
                sql.append(row == 0 ? "" : ", ")
                        .append("(?").append(first)
                        .append(", ?").append(first + 1)
                        .append(", ?").append(first + 2)
                        .append(", ?").append(first + 3)
                        .append(')');
            }
            MutationQuery statement = entityManager.unwrap(Session.class).createNativeMutationQuery(sql.toString());
            int parameter = 1;
            for (Listing listing : rows) {
                statement.setParameter(parameter++, listing.cveId(), String.class);
                statement.setParameter(parameter++, true, Boolean.class);
                statement.setParameter(parameter++, listing.dateAdded(), Instant.class);
                statement.setParameter(parameter++, updatedAt, Instant.class);
            }
            statement.executeUpdate();
        }
    }
}
