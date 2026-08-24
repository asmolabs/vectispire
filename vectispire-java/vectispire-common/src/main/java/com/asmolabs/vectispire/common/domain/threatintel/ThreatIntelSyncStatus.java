package com.asmolabs.vectispire.common.domain.threatintel;

import java.time.Instant;

/**
 * Status and health metrics of the live Threat Intelligence feed (CISA KEV & EPSS).
 */
public record ThreatIntelSyncStatus(
        Instant lastSyncedAt,
        long totalCves,
        long totalKev,
        String status,
        long backlogUpdatedCount) {}
