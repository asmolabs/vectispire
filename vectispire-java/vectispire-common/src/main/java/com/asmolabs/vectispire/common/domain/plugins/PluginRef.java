package com.asmolabs.vectispire.common.domain.plugins;

/**
 * A plugin as a task names it: its id and the digest of the manifest to run.
 *
 * <p>The executor fetches the manifest by both and refuses one that does not hash to {@code digest}
 * — the same reason {@code ScanTask} carries a rule set's hash rather than "the active set": an
 * executor that looked the plugin up for itself would run whatever it found when it asked, and two
 * executors taking turns on one target would resolve and reopen its plugin backlog.
 */
public record PluginRef(String id, String digest) {}
