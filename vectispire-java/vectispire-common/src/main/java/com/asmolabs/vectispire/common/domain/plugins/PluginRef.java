package com.asmolabs.vectispire.common.domain.plugins;

/**
 * A plugin as a task names it: its id and the digest of the manifest to run.
 *
 * <p>The executor fetches the manifest by both and refuses one that does not hash to {@code digest}
 * — the same reason {@code ScanTask} carries a rule set's hash rather than "the active set": an
 * executor that looked the plugin up for itself would run whatever it found when it asked, and two
 * executors taking turns on one target would resolve and reopen its plugin backlog.
 *
 * @param runsUnsigned the platform governor waived the signature requirement for this plugin, in
 *     writing and audited (decision 0017 §9.1): an executor requiring a signer runs it although its
 *     manifest declares none. It lifts nothing else — a signer the manifest declares is verified all
 *     the same. Absent from an older control plane's task, which reads as no waiver: the safe side.
 *     Taken from the control plane like the manifest itself, because it is of the same authority:
 *     the governor who could waive the requirement could as well register a signer of their own
 *     choosing, and what a signature defends against — a registry or a tag pushed by somebody else —
 *     is not the control plane
 */
public record PluginRef(String id, String digest, boolean runsUnsigned) {

    /** A plugin no waiver covers. */
    public PluginRef(String id, String digest) {
        this(id, digest, false);
    }
}
