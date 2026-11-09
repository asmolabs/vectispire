package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import java.util.List;
import java.util.Optional;

/**
 * The plugins, as a scan needs them: which ones a repository's scan runs, and a manifest by
 * reference.
 *
 * <p><b>A port, implemented by {@code plugins}</b> — the shape of {@link ScanRuleSets}, for the same
 * reason. The dispatcher decides the plugins when it builds the task, so two executors cannot
 * disagree about what was run; the built-in worker and the agent route answer a manifest by the
 * reference the task carries. {@code plugins} sits above {@code scanning} (it reads the backlog and
 * the targets), so the dependency points from it to here.
 */
public interface ScanPlugins {

    /**
     * The enabled plugins activated for the repository's project, each by id and current manifest
     * digest — empty for a repository filed in no project. Nothing is global.
     */
    List<PluginRef> forRepository(long repositoryId);

    /** The manifest a reference names, or empty when no plugin of that id ever had that digest. */
    Optional<PluginManifest> manifest(PluginRef reference);
}
