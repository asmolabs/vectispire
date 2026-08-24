package com.asmolabs.vectispire.common.domain.threatintel;

import java.time.Instant;

/**
 * Single CVE Threat Intelligence observation.
 */
public record ThreatIntelRecord(
        String cveId,
        boolean isKev,
        Double epssScore,
        Double epssPercentile,
        Instant dateAdded,
        String notes) {}
