package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import java.util.Arrays;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Whether four-eyes could be honoured today — the questions another module asks of the accounts
 * table before the setting is switched on.
 *
 * <p>The settings screen asks them before switching four-eyes on: with no active account holding a
 * role that {@link Role#canApproveTriage() may approve}, every decision would wait in a queue nobody
 * can empty; with fewer than two that {@link Role#canWriteGovernance() write governance}, a checklist
 * template could never be published, since its author may not publish it (decision 0032, question 9);
 * with fewer than two approvers, a project checklist its only approver wrote could never be signed off
 * (question 2). It read {@code UserRepository} itself until {@code access} became a module (a step-5
 * finding of decision 0028); the count is the same query, answered here.
 */
@Service
public class TriageApprovers {

    private static final List<String> APPROVER_ROLES = Arrays.stream(Role.values())
            .filter(Role::canApproveTriage)
            .map(Enum::name)
            .toList();

    private static final List<String> PUBLISHER_ROLES = Arrays.stream(Role.values())
            .filter(Role::canWriteGovernance)
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

    /**
     * Two, not one: under four-eyes a template version is published by somebody who did not write
     * it, and writing it takes the same role as publishing it. One governance writer can import a
     * draft that nobody may then publish — which surfaced only at the first publication.
     */
    @Transactional(readOnly = true)
    public boolean twoCanPublishTemplates() {
        return users.countActiveAdministratorsExcluding(PUBLISHER_ROLES, -1L) >= 2;
    }

    /**
     * Two approvers, not one: under four-eyes a project checklist is signed off by an approver who
     * wrote none of it, and approvers — a security champion above all — are who fills checklists in.
     * With one, every revision that approver answered, opened or submitted would be submitted and
     * never signed off, found at the first sign-off.
     */
    @Transactional(readOnly = true)
    public boolean twoCanSignOffChecklists() {
        return users.countActiveAdministratorsExcluding(APPROVER_ROLES, -1L) >= 2;
    }
}
