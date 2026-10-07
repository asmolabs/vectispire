package com.asmolabs.vectispire.common.domain.integrations;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import java.util.Map;

/**
 * A governor's switch refused because what the integration carries would be lost with it (decision 0040
 * §3): 409 of type {@code urn:vectispire:problem:integration-in-use}, with the integration's key in the
 * member {@code integration}.
 *
 * <p><b>Its own cause, not {@code integration-disabled}</b>: the gesture that resolves it is another one.
 * {@code integration-disabled} asks a governor to switch something on; this asks whoever owns the
 * configuration that uses the integration — the SIEM export's security lead — to point it elsewhere first,
 * and a client that branched on one token would send its user to the wrong screen.
 *
 * <p>The sentence names what uses it and why that matters, because the refusal is the only place a
 * governor learns it: a SIEM transport switched off under the export would leave the security events
 * queued in the outbox with nowhere to go — lost in silence, the failure decision 0025 exists to prevent.
 */
public class IntegrationInUseException extends ConflictException {

    /** The token the problem's {@code type} ends with; stated in the API's reference, so it does not move. */
    public static final String CAUSE = "integration-in-use";

    private final transient Integration integration;

    /** @param use what uses it and what to change first, as a sentence the refusal ends with */
    public IntegrationInUseException(Integration integration, String use) {
        super("The integration \"" + integration.key() + "\" is in use and cannot be disabled: " + use, CAUSE,
                Map.of("integration", integration.key()));
        this.integration = integration;
    }

    public Integration integration() {
        return integration;
    }
}
