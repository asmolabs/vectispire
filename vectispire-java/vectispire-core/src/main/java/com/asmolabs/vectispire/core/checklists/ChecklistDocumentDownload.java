package com.asmolabs.vectispire.core.checklists;

/**
 * A revision's document as the route hands it over: a zip of {@code checklist.xlsx} and {@code
 * checklist.json}, with their detached signatures when the revision was signed off (decision 0032 §10).
 *
 * @param signed whether this is the package signed inside the sign-off, served as stored; false for a
 *     revision rendered on request, which carries no signature
 * @param sha256 the package's SHA-256
 */
public record ChecklistDocumentDownload(String fileName, boolean signed, String sha256, byte[] content) {}
