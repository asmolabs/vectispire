package com.asmolabs.vectispire.common.scanning;

/**
 * A plugin the executor would not start, and why — {@link PluginStep.Refused}, not absent.
 *
 * <p>A failure of the scan like any other a scanner throws, so that whatever catches those still
 * records it; the refusal is what lets the step say "not signed" rather than "crashed".
 */
public final class PluginRefusedException extends ScannerFailureException {

    private final PluginStep.Refusal refusal;

    public PluginRefusedException(String label, PluginStep.Refusal refusal, String message) {
        super(label, message);
        this.refusal = refusal;
    }

    public PluginStep.Refusal refusal() {
        return refusal;
    }
}
