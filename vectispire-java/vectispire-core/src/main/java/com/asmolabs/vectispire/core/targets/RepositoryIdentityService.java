package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.targets.RepositoryIdentity;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Gives every repository row its identity and, where it is free, its guard (V74).
 *
 * <p><b>Why after the start, and every hour.</b> The identity is computed in Java, so the migration
 * leaves both columns null; until a row holds its guard, the routes' check cannot see it, and a second
 * filing of it would be accepted. So the rows are keyed by the maintenance turn, thirty seconds after
 * the start and every hour after — every hour because an instance of the previous version, still
 * serving during a rolling upgrade, writes rows without one.
 *
 * <p><b>Oldest first, and nothing taken from anyone.</b> Of two rows already filing the same target,
 * the older takes the guard and the younger keeps null: both stay served and scanned, and the pair is
 * listed by {@code GET /api/v1/repositories/duplicates} until an administrator merges it. A write
 * refused because a creation took the guard in between leaves the row for the next turn.
 *
 * <p><b>Every instance runs it</b>, as every maintenance task: each write is conditional on the row
 * still holding no guard and still naming what was read, so two instances keying together write one
 * value and the second finds nothing to do.
 */
@Service
public class RepositoryIdentityService {

    private static final Logger log = LoggerFactory.getLogger(RepositoryIdentityService.class);

    private final GitRepositoryRepository repositories;

    public RepositoryIdentityService(GitRepositoryRepository repositories) {
        this.repositories = repositories;
    }

    /**
     * What one turn did.
     *
     * @param keyed rows that took their guard
     * @param twins rows left without one because another row files the same target
     */
    public record Keyed(int keyed, int twins) {}

    public Keyed keyUnkeyed() {
        int keyed = 0;
        int twins = 0;
        for (RepositoryEntity row : repositories.findByIdentityGuardIsNullOrderByIdAsc()) {
            Optional<RepositoryIdentity> identity =
                    RepositoryIdentity.of(row.getUrl(), row.getBranch(), row.getSubPath());
            if (identity.isEmpty()) {
                // A URL that names no host — a row older than the URL's validation. Nothing to compare.
                continue;
            }
            RepositoryIdentity target = identity.get();
            boolean free = repositories.findByIdentityGuard(target.guard()).isEmpty();
            if (!free && Objects.equals(row.getUrlIdentity(), target.repository())) {
                twins++;
                continue;
            }
            try {
                int written = repositories.key(row.getId(), row.getUrl(), row.getBranch(),
                        row.getSubPath() == null ? "" : row.getSubPath(), target.repository(), free ? target.guard() : null);
                if (written == 1 && free) {
                    keyed++;
                } else if (written == 1) {
                    twins++;
                }
            } catch (RuntimeException refused) {
                // Most likely a creation took the guard between the read and the write. Whatever it was,
                // the row is as it was, and the next turn reads it again.
                log.debug("Repository {} was not keyed this turn: {}", row.getId(), refused.getMessage());
            }
        }
        if (keyed > 0) {
            log.info("{} repository target(s) received their identity", keyed);
        }
        return new Keyed(keyed, twins);
    }
}
