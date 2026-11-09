package com.asmolabs.vectispire.core.access;

import java.util.Optional;
import java.util.UUID;

/**
 * Which agent holds an API key — the one thing authentication needs to know about the agent row.
 *
 * <p><b>A port, because the row is {@code agents}'.</b> An agent key authenticates to an agent, so
 * the bearer filter has to turn a key into the {@link AgentView} the principal carries. The row
 * stayed layered through step 4 for exactly that reason: {@code access} read it, while {@code agents}
 * administers it and sits above {@code access}. Declared here and implemented by {@code agents}, the
 * lookup keeps {@code access} below every domain and lets the row move to the module that writes it
 * (decision 0029).
 */
public interface AgentDirectory {

    /** The agent this key was issued to, or empty when the key is an account's or unknown. */
    Optional<AgentView> byApiKey(UUID apiKeyId);
}
