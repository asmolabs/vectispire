package com.asmolabs.vectispire.core.platform;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.settings.IntegrationView;
import com.asmolabs.vectispire.core.settings.Integrations;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * The platform governor's switches over the integrations' registry (decision 0040, lot I1): the list a
 * screen filters its forms with, and the gesture that switches one on or off.
 *
 * <p><b>Here and not beside the registry</b>, as {@link SettingsAdministrationService} sits above {@code
 * SettingsService}: the gesture records an audit entry, and {@code settings}, which every module reads,
 * may use nothing — {@code audit} included.
 *
 * <p><b>Each switch is a governance gesture</b> (0040 §4): audited as {@code INTEGRATION_ENABLED_CHANGED},
 * which the SIEM receives as a security setting change ({@code VECTI-SEC-019}); the same state again
 * records nothing. The entry is written after the switch has committed — {@code Integrations.switchTo}
 * opens and closes its own transaction — so it never records a change that rolled back, nor holds the
 * audit chain's lock inside one.
 *
 * <p><b>Not yet under four-eyes.</b> 0040 §4 allows enabling — the direction that widens what the
 * installation reaches — to be put under the same four-eyes setting as plugin registration; lot I1 leaves
 * it to the governor alone, and disabling, which narrows it, needs no second person in any case.
 */
@Service
public class IntegrationAdministrationService {

    private final Integrations integrations;
    private final AuditLogService audit;

    public IntegrationAdministrationService(Integrations integrations, AuditLogService audit) {
        this.integrations = integrations;
        this.audit = audit;
    }

    /**
     * Every integration with its state, for any signed-in reader: the screens that offer a forge, a tracker
     * or a channel need to know which are on. Who switched one is governance's trail, shown to the roles
     * that read governance only — an ordinary account learns what is on, not which administrator decided.
     */
    public List<IntegrationView> list(UserView reader) {
        boolean readsGovernance = Role.of(reader.role()).map(Role::hasGlobalSecurityScope).orElse(false);
        List<IntegrationView> all = integrations.list();
        return readsGovernance ? all : all.stream().map(IntegrationView::withoutAuthor).toList();
    }

    /**
     * Switches one integration on or off.
     *
     * @param key the integration's key, {@code <family>.<name>}
     * @param enabled the state wanted; null is refused, never read as off
     * @throws NotFoundException for a key no integration has
     * @throws InvalidInputException without a state
     */
    public IntegrationView setEnabled(String key, Boolean enabled, UserView governor, RequestActor actor) {
        Integration integration = Integration.byKey(key).orElseThrow(() -> new NotFoundException("Integration not found."));
        if (enabled == null) {
            throw new InvalidInputException("Say whether the integration is enabled.");
        }
        Integrations.Switched switched = integrations.switchTo(integration, enabled, governor.username());
        if (switched.changed()) {
            audit.record(actor.entry(AuditOperation.INTEGRATION_ENABLED_CHANGED, integration.key(),
                    "Integration \"" + integration.key() + "\" " + (enabled
                            ? "enabled: the installation may talk to it again."
                            : "disabled: the installation no longer talks to it; what uses it is kept.")));
        }
        return switched.integration();
    }
}
