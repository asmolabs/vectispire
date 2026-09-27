package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.PluginActivationEntity;
import java.time.Instant;

/** A plugin switched on for a project, under the entity's property names. */
public record PluginActivationView(Long id, String pluginId, Long projectId, Instant activatedAt, String activatedBy) {

    static PluginActivationView of(PluginActivationEntity activation) {
        return new PluginActivationView(activation.getId(), activation.getPluginId(), activation.getProjectId(),
                activation.getActivatedAt(), activation.getActivatedBy());
    }
}
