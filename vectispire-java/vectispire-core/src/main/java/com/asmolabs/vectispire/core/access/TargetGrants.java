package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyEntity;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetRepository;
import com.asmolabs.vectispire.core.access.persistence.UserTargetRepository;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The grants naming one target, to accounts and to teams, revoked together.
 *
 * <p><b>Why anybody outside {@code access} needs this.</b> A grant names its target as {@code (kind,
 * id)}, which no foreign key can follow into three tables, so nothing cascades: whoever deletes a
 * repository, an image or a project has to revoke what names it, or the row stays on the grant
 * screens — and, should an engine hand the identifier out again, grants a target nobody chose (see
 * {@link UserTargetRepository#deleteByTarget}). The deleting module used to write both grant tables itself
 * (a step-5 finding of decision 0028); it now asks here.
 */
@Service
public class TargetGrants {

    private final UserTargetRepository userTargets;
    private final TeamTargetRepository teamTargets;
    private final ApiKeyRepository keys;

    public TargetGrants(UserTargetRepository userTargets, TeamTargetRepository teamTargets, ApiKeyRepository keys) {
        this.userTargets = userTargets;
        this.teamTargets = teamTargets;
        this.keys = keys;
    }

    /**
     * What went with a target: how many grants, and which keys — named, because each revoked key is
     * an audit entry of its own.
     *
     * <p>The keys are listed rather than counted. A pipeline that stops authenticating the day its
     * repository was deleted is found, by whoever runs it, in the log under the key's own id; a count
     * in the deletion's entry would say that some key went and not which.
     */
    public record Revoked(int grants, List<RevokedKey> keys) {

        public Revoked {
            keys = List.copyOf(keys);
        }

        /** Whether anybody's access changed — the deletion's entry signals it when so. */
        public boolean changedAccess() {
            return grants > 0 || !keys.isEmpty();
        }

        /** For the deletion's audit entry: what went with the target, in words. */
        public String summary() {
            return grants + " grant(s) and " + keys.size() + " API key(s) revoked";
        }
    }

    /**
     * Who holds a grant naming one target: accounts directly, and teams — each team's members seeing it through
     * the team. Counted, not named: the import preview that asks (decision 0037 §4) tells an administrator how
     * far the new targets reach, and the grant screens name the holders.
     */
    public record Grantees(long accounts, long teams) {

        public static final Grantees NONE = new Grantees(0, 0);
    }

    /**
     * The grantees of each of these projects that has any; a project missing from the answer has none. One pair
     * of counts per project — a preview asks of the projects an import files into, a few hundred at most.
     */
    @Transactional(readOnly = true)
    public Map<Long, Grantees> granteesOfProjects(Collection<Long> projectIds) {
        Map<Long, Grantees> granted = new HashMap<>();
        for (Long projectId : new HashSet<>(projectIds)) {
            Grantees grantees = new Grantees(
                    userTargets.countByTarget(TeamRules.KIND_PROJECT, projectId),
                    teamTargets.countByTarget(TeamRules.KIND_PROJECT, projectId));
            if (grantees.accounts() > 0 || grantees.teams() > 0) {
                granted.put(projectId, grantees);
            }
        }
        return Map.copyOf(granted);
    }

    /** A key revoked with its target, as its audit entry names it. */
    public record RevokedKey(UUID id, String name) {}

    /**
     * Revokes every grant naming the target — and the integration keys restricted to it, which are a
     * grant of the same shape — and says what went.
     *
     * <p>{@code MANDATORY}: the revocation belongs to the deletion that causes it. Committed on its
     * own, a deletion that then rolled back would leave its target standing and its grants gone. The
     * caller audits what this answers once its transaction has committed.
     *
     * <p><b>The keys too, and the key itself, never its restriction.</b> A key restricted to a
     * repository names it as {@code (kind, id)} like a grant, and was left behind by the deletion:
     * useless while the identifier stays unused — the supported engines never reuse one — and pointed
     * at somebody else's target the day a restore renumbers. Clearing the restriction instead would be
     * the one wrong answer: a key without one acts with its account's whole visibility, so the
     * pipeline key for one repository would wake up reading the estate. Here rather than in a listener
     * of {@code TargetDeleted}: {@code access} sits below {@code targets}, so the publisher calls it
     * before the first phase, as it calls for the grants. An agent's key is not revoked: it belongs to
     * its agent.
     *
     * <p>The keys are read, then deleted by id, so that the entries name exactly the rows that went.
     *
     * @param kind as the grant tables store it — {@code TeamRules.KIND_REPOSITORY}, {@code
     *     KIND_CONTAINER} or {@code KIND_PROJECT}
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public Revoked revokeAll(String kind, long targetId) {
        int grants = userTargets.deleteByTarget(kind, targetId) + teamTargets.deleteByTarget(kind, targetId);
        List<RevokedKey> restricted = keys.findRestrictedTo(kind, targetId).stream()
                .map(TargetGrants::revoked)
                .toList();
        if (!restricted.isEmpty()) {
            keys.revokeByIds(restricted.stream().map(RevokedKey::id).toList());
        }
        return new Revoked(grants, restricted);
    }

    private static RevokedKey revoked(ApiKeyEntity key) {
        return new RevokedKey(key.getId(), key.getName());
    }
}
