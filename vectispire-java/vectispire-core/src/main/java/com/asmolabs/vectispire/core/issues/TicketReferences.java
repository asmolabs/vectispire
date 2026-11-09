package com.asmolabs.vectispire.core.issues;

import java.util.Optional;

/**
 * Whether a ticket reference is one the configured tracker issues.
 *
 * <p><b>Declared here, implemented by {@code tickets}.</b> Attaching a ticket is an issue's decision,
 * but what a valid reference looks like is the tracker's knowledge, and {@code tickets} already
 * depends on {@code issues} — its webhook and its sweep transition issues. Calling the tracker's
 * service from here closed a cycle between the two domains; the port turns the edge around, as
 * decision 0026 prescribes for a lower domain that needs a higher one.
 */
public interface TicketReferences {

    /**
     * @param reference trimmed, non-empty, and within the column's length
     * @return empty when the reference is acceptable; otherwise the sentence the person who typed
     *     it is answered with
     * @throws com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException while the
     *     configured tracker's integration is switched off (decision 0040 §3): 409, not a 400 about the
     *     reference — the same reference is accepted once it is switched back on
     */
    Optional<String> refusal(String reference);
}
