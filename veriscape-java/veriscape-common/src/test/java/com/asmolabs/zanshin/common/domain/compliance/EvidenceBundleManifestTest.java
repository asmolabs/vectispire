package com.asmolabs.zanshin.common.domain.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("EvidenceBundleManifest structured evidence representation")
class EvidenceBundleManifestTest {

    @Test
    @DisplayName("records bundle metadata and file checksums")
    void recordsManifestMetadata() {
        EvidenceBundleManifest.EvidenceFileEntry file = new EvidenceBundleManifest.EvidenceFileEntry(
                "immutable_audit_log.jsonl",
                "Cryptographic HMAC audit ledger",
                1024,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        EvidenceBundleManifest manifest = new EvidenceBundleManifest(
                "1.0",
                Instant.parse("2026-08-22T10:00:00Z"),
                "ciso@corp.internal",
                "VERIFIED_INTACT",
                150,
                List.of(file));

        assertThat(manifest.version()).isEqualTo("1.0");
        assertThat(manifest.auditChainStatus()).isEqualTo("VERIFIED_INTACT");
        assertThat(manifest.files()).hasSize(1);
        assertThat(manifest.files().get(0).path()).isEqualTo("immutable_audit_log.jsonl");
    }
}
