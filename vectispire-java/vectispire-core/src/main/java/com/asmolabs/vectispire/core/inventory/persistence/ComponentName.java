package com.asmolabs.vectispire.core.inventory.persistence;

/**
 * A component row as the licence inventory reads it: which scan, and what it names. The other
 * columns — its type, its target, the scan's instant — the inventory has from the scan.
 *
 * @param origin as stored: null for the scanner, {@code build} or {@code both} ({@code ComponentOrigin})
 * @param scannedVersion for {@code both}, the version the scanner wrote, which its SBOM keys the licence by
 * @param declaredLicense the licence the build declared, or null
 */
public record ComponentName(Long scanId, String name, String version, String purl, String origin, String scannedVersion,
        String declaredLicense) {}
