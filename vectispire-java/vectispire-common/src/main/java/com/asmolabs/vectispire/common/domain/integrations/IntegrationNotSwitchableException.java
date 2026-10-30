package com.asmolabs.vectispire.common.domain.integrations;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import java.util.Map;

/**
 * A governor's switch-off refused because this version cannot honour it (decision 0040 §1, "disabled is
 * unreachable"): 409 of type {@code urn:vectispire:problem:integration-not-switchable}, with the integration's
 * key in the member {@code integration}.
 *
 * <p>The AI providers and the notification channels are listed in the registry but none of their adapters
 * asks it yet (lots I5 and the notification half of I6). Accepting the switch would record and audit a
 * suspension that suspends nothing — the AI review would go on sending code to the provider the governor
 * had just "disabled". A refusal is the honest answer until the adapters are wired; it names what does stop
 * them today.
 *
 * <p><b>Its own cause</b>, neither {@code integration-disabled} nor {@code integration-in-use}: no gesture of
 * the caller's resolves it — a later version does.
 */
public class IntegrationNotSwitchableException extends ConflictException {

    /** The token the problem's {@code type} ends with; stated in the API's reference, so it does not move. */
    public static final String CAUSE = "integration-not-switchable";

    private final transient Integration integration;

    public IntegrationNotSwitchableException(Integration integration) {
        super("The integration \"" + integration.key() + "\" cannot be disabled yet: this version's "
                + integration.family().wireName() + " adapters do not consult the registry, so disabling it would "
                + "stop nothing. " + howToStop(integration.family()), CAUSE, Map.of("integration", integration.key()));
        this.integration = integration;
    }

    private static String howToStop(IntegrationFamily family) {
        return switch (family) {
            case AI -> "To stop the AI review, turn ai_review_enabled off in the settings.";
            case NOTIFICATION -> "To stop a notification channel, empty its URL or its recipients in the notification "
                    + "settings, and a team's own webhook on that team.";
            default -> "";
        };
    }

    public Integration integration() {
        return integration;
    }
}
