package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;

/**
 * How an executor obtains the manifest a task names.
 *
 * <p>The seam {@link RulePlacement.RuleSetProvider} already is, for code instead of rules: the
 * built-in worker reads the control plane's tables, a remote agent asks the protocol, and the runner
 * — which runs on both sides and may reach neither a database nor HTTP — knows only this. Whatever
 * comes back is checked against the reference's digest by the runner, not by the provider, so a
 * provider that answers the wrong manifest fails the step instead of running it.
 */
@FunctionalInterface
public interface PluginProvider {

    /** @throws RuntimeException when the manifest cannot be obtained; the plugin's step is then absent */
    PluginManifest manifest(PluginRef reference);

    /** For an executor that cannot fetch plugins: every plugin a task names is absent, loudly. */
    PluginProvider NONE = reference -> {
        throw new IllegalStateException("This executor has no way to fetch plugin " + reference.id() + ".");
    };
}
