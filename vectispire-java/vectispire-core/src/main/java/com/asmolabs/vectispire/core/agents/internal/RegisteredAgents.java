package com.asmolabs.vectispire.core.agents.internal;

import com.asmolabs.vectispire.core.access.AgentDirectory;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** {@code access}'s {@link AgentDirectory}, answered from the agent row this module owns. */
@Service
public class RegisteredAgents implements AgentDirectory {

    private final AgentRepository agents;

    public RegisteredAgents(AgentRepository agents) {
        this.agents = agents;
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<AgentView> byApiKey(UUID apiKeyId) {
        return agents.findByApiKeyId(apiKeyId).map(AgentViews::of);
    }
}
