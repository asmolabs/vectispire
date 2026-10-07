package com.asmolabs.vectispire.common.domain.integrations;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import java.util.Map;

/**
 * A gesture refused because the integration it needs is switched off on this installation (decision 0040
 * §1): 409 of type {@code urn:vectispire:problem:integration-disabled}, with the integration's key in the
 * member {@code integration}, so that a screen names it in its own language without parsing the sentence.
 *
 * <p>A conflict, not a 403: the caller may well be allowed to do this, and the same request succeeds
 * unchanged once a governor enables the integration. Not a 404 either — the adapter exists, and saying so
 * discloses nothing a caller of the registry's list does not already read.
 */
public class IntegrationDisabledException extends ConflictException {

    /** The token the problem's {@code type} ends with; stated in the API's reference, so it does not move. */
    public static final String CAUSE = "integration-disabled";

    private final transient Integration integration;

    public IntegrationDisabledException(Integration integration) {
        super("The integration \"" + integration.key() + "\" is disabled on this installation; the platform governor "
                + "enables it under Administration → Integrations.", CAUSE, Map.of("integration", integration.key()));
        this.integration = integration;
    }

    public Integration integration() {
        return integration;
    }
}
