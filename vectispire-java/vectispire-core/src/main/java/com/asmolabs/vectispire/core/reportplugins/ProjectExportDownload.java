package com.asmolabs.vectispire.core.reportplugins;

/**
 * A project's export as it is handed over: a zip holding {@code export.json} and {@code export.json.sig},
 * the detached signature by the platform's key.
 *
 * @param exportSha256 the SHA-256 of {@code export.json} — the digest the audit entry names, and the one a
 *     report's provenance will
 */
public record ProjectExportDownload(String fileName, String exportSha256, byte[] content) {}
