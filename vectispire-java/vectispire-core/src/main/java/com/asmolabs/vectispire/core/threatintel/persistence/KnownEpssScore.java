package com.asmolabs.vectispire.core.threatintel.persistence;

/**
 * One CVE's EPSS score and percentile as stored — the identifier upper-case — for the readers that
 * need the figures and not the row: a scan's enrichment, the backlog's refresh, a lookup.
 */
public record KnownEpssScore(String cveId, double score, double percentile) {}
