package com.asmolabs.vectispire.common.domain.compliance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Locale;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a framework named by a path segment")
class ComplianceFrameworkIdentifierTest {

    @Test
    @DisplayName("is found whatever the server's default locale")
    void independentOfTheLocale() {
        Locale previous = Locale.getDefault();
        try {
            // Turkish upper-cases "i" to a dotted capital: "pci_dss" would become "PCİ_DSS".
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            assertThat(ComplianceFramework.fromIdentifier("pci_dss")).isEqualTo(ComplianceFramework.PCI_DSS);
            assertThat(ComplianceFramework.fromIdentifier("iso-27001")).isEqualTo(ComplianceFramework.ISO_27001);
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    @DisplayName("ignores separators, and refuses what names nothing with the list of what does")
    void separatorsAside() {
        assertThat(ComplianceFramework.fromIdentifier("NIS2")).isEqualTo(ComplianceFramework.NIS_2);
        assertThat(ComplianceFramework.fromIdentifier("eu-cra")).isEqualTo(ComplianceFramework.EU_CRA);
        assertThatThrownBy(() -> ComplianceFramework.fromIdentifier("hipaa"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ISO_27001");
    }
}
