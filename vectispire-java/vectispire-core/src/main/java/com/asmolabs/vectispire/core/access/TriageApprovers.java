package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import java.util.Arrays;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Whether anybody could approve a triage today — the one question another module asks of the
 * accounts table.
 *
 * <p>The settings screen asks it before switching four-eyes on: with no active account holding a
 * role that {@link Role#canApproveTriage() may approve}, every decision would wait in a queue nobody
 * can empty. It read {@code UserRepository} itself until {@code access} became a module (a step-5 finding of
 * decision 0028); the count is the same query, answered here.
 */
@Service
public class TriageApprovers {

    private static final List<String> APPROVER_ROLES = Arrays.stream(Role.values())
            .filter(Role::canApproveTriage)
            .map(Enum::name)
            .toList();

    private final UserRepository users;

    public TriageApprovers(UserRepository users) {
        this.users = users;
    }

    /**
     * Counted in the database rather than deduced from a role: the question is about
     * <em>active</em> accounts, and an estate may perfectly well declare a role nobody holds.
     */
    @Transactional(readOnly = true)
    public boolean anyActive() {
        return users.countActiveAdministratorsExcluding(APPROVER_ROLES, -1L) > 0;
    }
}
