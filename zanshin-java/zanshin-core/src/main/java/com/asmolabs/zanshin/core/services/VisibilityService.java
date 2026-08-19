package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.access.Visibility;
import com.asmolabs.zanshin.common.domain.access.VisibilityMode;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.common.domain.users.Role;
import com.asmolabs.zanshin.core.persistence.AgentEntity;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.persistence.UserTargetEntity;
import com.asmolabs.zanshin.core.repositories.UserTargets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * What this caller may see, resolved once and asked everywhere.
 *
 * <p><b>One resolution point, one enforcement point.</b> The rule itself is {@link Visibility},
 * which is pure and exhaustively tested; this class only answers "which one applies to the
 * request in hand". Splitting it that way is what makes the interesting cases — an unassigned
 * account, an intersecting API key — testable without a database.
 *
 * <p><b>Administrators always see everything.</b> Not a convenience: somebody has to be able to
 * make the assignments, and an administrator who cannot see a target cannot assign it.
 */
@Service
public class VisibilityService {

    private static final String KIND_REPOSITORY = "repository";
    private static final String KIND_CONTAINER = "container";

    private final SettingsService settings;
    private final UserTargets assignments;

    public VisibilityService(SettingsService settings, UserTargets assignments) {
        this.settings = settings;
        this.assignments = assignments;
    }

    public VisibilityMode mode() {
        return VisibilityMode.of(settings.get(Setting.TARGET_VISIBILITY));
    }

    /**
     * The visibility of a signed-in account.
     *
     * @param restriction a further narrowing carried by the credential — an API key issued for
     *     one target. Intersected, never unioned: a narrow key held by a broad account stays
     *     narrow
     */
    @Transactional(readOnly = true)
    public Visibility of(UserEntity user, Visibility restriction) {
        return accountVisibility(user).and(restriction);
    }

    @Transactional(readOnly = true)
    public Visibility of(UserEntity user) {
        return accountVisibility(user);
    }

    /**
     * An agent's visibility.
     *
     * <p>Everything, and deliberately: an agent does not read the backlog at all — its four
     * routes claim work and hand results back, and the work it is given is already narrowed by
     * the queue's own label routing. Restricting it here would express nothing and suggest the
     * agent protocol goes through these filters, which it does not.
     */
    public Visibility of(AgentEntity agent) {
        return Visibility.everything();
    }

    private Visibility accountVisibility(UserEntity user) {
        if (user == null) {
            // No account, no visibility. Reached only if a route forgot its marker, and the safe
            // answer to "who is this" being unanswerable is "nothing".
            return Visibility.only(List.of());
        }
        if (mode() == VisibilityMode.EVERYONE || isAdministrative(user)) {
            return Visibility.everything();
        }

        List<ScanTarget> assigned = new ArrayList<>();
        for (UserTargetEntity row : assignments.findByUserId(user.getId())) {
            targetOf(row.getId().targetKind(), row.getId().targetId()).ifPresent(assigned::add);
        }
        return Visibility.only(assigned);
    }

    /**
     * The restriction an API key carries, if any.
     *
     * <p><b>This was declared and never enforced.</b> The key row has carried {@code targetKind}
     * and {@code targetId} from the start, the administration screen offers to restrict a key to
     * one target, and the controller even checks that the target exists — while nothing read the
     * columns again. A key advertised as "restricted to repository 5" could read everything,
     * which is worse than no restriction at all: the interface promised one.
     */
    public Visibility restrictionOf(String targetKind, Long targetId) {
        if (targetKind == null || targetId == null) {
            return Visibility.everything();
        }
        return targetOf(targetKind, targetId)
                .map(target -> Visibility.only(List.of(target)))
                // A kind this version does not recognize restricts to nothing rather than to
                // everything: an unreadable restriction is still a restriction.
                .orElseGet(() -> Visibility.only(List.of()));
    }

    private static boolean isAdministrative(UserEntity user) {
        return Role.of(user.getRole()).map(Role::isAdministrative).orElse(false);
    }

    private static Optional<ScanTarget> targetOf(String kind, Long id) {
        if (KIND_REPOSITORY.equals(kind)) {
            return Optional.of(new ScanTarget.Repository(id));
        }
        if (KIND_CONTAINER.equals(kind)) {
            return Optional.of(new ScanTarget.Container(id));
        }
        return Optional.empty();
    }
}
