package com.asmolabs.vectispire.core.reportplugins;

/**
 * A produced report as it is handed over (decision 0035 §3): the package — the plugin's file, its detached
 * signature by the platform's key, and {@code provenance.json} — as one zip.
 *
 * @param packageSha256 the zip's SHA-256, as the download's audit entry names it
 */
public record ReportDocumentDownload(String fileName, String packageSha256, byte[] content) {}
