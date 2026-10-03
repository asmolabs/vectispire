package com.asmolabs.vectispire.core.inventory.persistence;

/**
 * A component row as the licence inventory reads it: which scan, and what it names. The other
 * columns — its type, its target, the scan's instant — the inventory has from the scan.
 */
public record ComponentName(Long scanId, String name, String version, String purl) {}
