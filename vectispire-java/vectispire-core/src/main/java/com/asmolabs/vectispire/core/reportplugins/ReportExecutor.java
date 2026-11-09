package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.scanning.scanners.ReportPluginRenderer;

/**
 * Where a report plugin runs: the control plane's container endpoint (decision 0035 §2) — the Docker endpoint the
 * built-in worker uses, the socket proxy of 0018, never an agent.
 *
 * <p><b>A bean only where that endpoint exists.</b> An installation whose built-in worker is switched off has every
 * scan on agents and nothing here to run a report with: no bean, and a request is answered 409 {@code
 * report-executor-unavailable} rather than queued for nobody to claim. Running on an agent, with an export sealed
 * to it, is a later lot.
 */
public interface ReportExecutor {

    /**
     * Renders {@code export} with the plugin — its signer verified, in the closed shape — and says what came of it.
     *
     * @param manifest the plugin's approved manifest
     */
    ReportPluginRenderer.Outcome render(ReportPluginManifest manifest, byte[] export);
}
