package com.asmolabs.vectispire.core.plugins.internal;

import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.core.plugins.PluginService;
import com.asmolabs.vectispire.core.scanning.ScanPlugins;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/** {@code scanning}'s {@link ScanPlugins}, answered by this module's registry. */
@Component
public class PluginsForScans implements ScanPlugins {

    private final PluginService plugins;

    public PluginsForScans(PluginService plugins) {
        this.plugins = plugins;
    }

    @Override
    public List<PluginRef> forRepository(long repositoryId) {
        return plugins.forRepository(repositoryId);
    }

    @Override
    public Optional<PluginManifest> manifest(PluginRef reference) {
        return plugins.manifest(reference);
    }
}
