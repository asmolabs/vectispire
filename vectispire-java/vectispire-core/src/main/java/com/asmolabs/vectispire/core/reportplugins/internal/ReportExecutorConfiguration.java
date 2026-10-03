package com.asmolabs.vectispire.core.reportplugins.internal;

import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.scanners.ReportPluginRenderer;
import com.asmolabs.vectispire.core.reportplugins.ReportExecutor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The report executor, on the control plane's own container endpoint (decision 0035 §2).
 *
 * <p><b>Under the built-in worker's condition</b>, {@code vectispire.worker.enabled}: the worker's runner and this
 * one reach the same endpoint — {@code VECTISPIRE_DOCKER_HOST} or {@code DOCKER_HOST}, the socket proxy in the
 * shipped composition — and an operator who switched the worker off said this control plane has none. Without the
 * bean a report request is refused as {@code report-executor-unavailable}, never queued for nobody.
 *
 * <p>The plugins' mirror is the scanner plugins' ({@code VECTISPIRE_PLUGIN_REGISTRY}): one registry an estate
 * mirrors plugin images into, which must carry their signatures too. The scanner plugins' {@code
 * plugin-signature-required} is deliberately not read: a report plugin's signer is required whatever it says.
 */
@Configuration
@ConditionalOnProperty(prefix = "vectispire.worker", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ReportExecutorConfiguration {

    @Bean
    ReportExecutor reportExecutor(@Value("${vectispire.scanning.plugin-registry:}") String pluginRegistry) {
        ReportPluginRenderer renderer = new ReportPluginRenderer(new ContainerRunner(), pluginRegistry);
        return renderer::render;
    }
}
