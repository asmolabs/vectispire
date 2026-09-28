package com.asmolabs.vectispire.core.checklists;

/**
 * An uploaded proof's bytes, for the download route alone — which serves them as an attachment and
 * never as the declared media type (decision 0032 §5, open question 13).
 */
public record ChecklistEvidenceDownload(String fileName, String sha256, byte[] content) {}
