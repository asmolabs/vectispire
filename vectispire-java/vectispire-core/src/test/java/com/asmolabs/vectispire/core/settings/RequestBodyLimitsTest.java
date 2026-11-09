package com.asmolabs.vectispire.core.settings;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.util.unit.DataSize;

/**
 * The body ceilings as the application binds them. The defaults were written twice — on the filter
 * and on the service checking the same body again — and are now written once, so they are pinned here.
 */
@DisplayName("the request body ceilings' configuration")
class RequestBodyLimitsTest {

    private static RequestBodyLimits bound(Map<String, String> properties) {
        return new Binder(new MapConfigurationPropertySource(properties))
                .bindOrCreate("vectispire.http.max-body", RequestBodyLimits.class);
    }

    @Test
    @DisplayName("unset, each route keeps the ceiling it shipped with")
    void theDefaults() {
        RequestBodyLimits limits = bound(Map.of());

        assertThat(limits.ticketWebhook()).isEqualTo(DataSize.ofMegabytes(1));
        assertThat(limits.vexIngest()).isEqualTo(DataSize.ofMegabytes(16));
        assertThat(limits.agentResult()).isEqualTo(DataSize.ofMegabytes(256));
        assertThat(limits.signIn()).isEqualTo(DataSize.ofKilobytes(16));
        assertThat(limits.sarifImport()).isEqualTo(DataSize.ofMegabytes(32));
        assertThat(limits.coverageImport()).isEqualTo(DataSize.ofMegabytes(16));
        assertThat(limits.testReportImport()).isEqualTo(DataSize.ofMegabytes(32));
        assertThat(limits.sbomImport()).isEqualTo(DataSize.ofMegabytes(32));
        assertThat(limits.checklistTemplateImport()).isEqualTo(DataSize.ofMegabytes(10));
        assertThat(limits.checklistEvidence()).isEqualTo(DataSize.ofMegabytes(25));
        assertThat(limits.ruleSetUpload()).isEqualTo(DataSize.ofMegabytes(64));
        assertThat(limits.fallback()).isEqualTo(DataSize.ofMegabytes(1));
    }

    @Test
    @DisplayName("the default ceiling is still read from `default`, a key no record component can be named")
    void theDefaultKeyBindsTheFallback() {
        RequestBodyLimits limits = bound(Map.of(
                "vectispire.http.max-body.default", "2MB",
                "vectispire.http.max-body.sarif-import", "48MB"));

        assertThat(limits.fallback()).isEqualTo(DataSize.ofMegabytes(2));
        assertThat(limits.sarifImport()).isEqualTo(DataSize.ofMegabytes(48));
    }
}
