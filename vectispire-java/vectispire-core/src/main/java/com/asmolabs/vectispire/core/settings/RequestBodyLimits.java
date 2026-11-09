package com.asmolabs.vectispire.core.settings;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.context.properties.bind.Name;
import org.springframework.util.unit.DataSize;
import org.springframework.validation.annotation.Validated;

/**
 * How large a request body each route accepts, {@code vectispire.http.max-body.*}.
 *
 * <p><b>One record, because two readers each held a default.</b> The body filter refuses a request
 * past its route's ceiling; four services check the same ceiling again on what they parse — a
 * workbook, a proof's file, an imported report — and each carried its own copy of the default
 * beside the filter's. Raising one in a later release and not the other would have accepted a body
 * at the door and refused it inside. Here, in the shared settings module, where the filter and every
 * service may read it.
 *
 * <p>Why each route has its own ceiling is told on {@code RequestBodyLimitFilter}.
 *
 * @param fallback {@code default}: every route without a ceiling of its own
 */
@Validated
@ConfigurationProperties("vectispire.http.max-body")
public record RequestBodyLimits(
        @DefaultValue("1MB") DataSize ticketWebhook,
        @DefaultValue("16MB") DataSize vexIngest,
        @DefaultValue("256MB") DataSize agentResult,
        @DefaultValue("16KB") DataSize signIn,
        @DefaultValue("32MB") DataSize sarifImport,
        @DefaultValue("16MB") DataSize coverageImport,
        @DefaultValue("32MB") DataSize testReportImport,
        @DefaultValue("32MB") DataSize sbomImport,
        @DefaultValue("10MB") DataSize checklistTemplateImport,
        @DefaultValue("25MB") DataSize checklistEvidence,
        @DefaultValue("64MB") DataSize ruleSetUpload,
        @Name("default") @DefaultValue("1MB") DataSize fallback) {}
