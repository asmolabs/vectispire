package com.asmolabs.vectispire.core.plugins;

/**
 * A coverage or test report refused for what the caller is or claims, not for the document's form: a
 * session rather than a declared source's key, a key no enabled source is declared for, a kind its
 * source may not deliver.
 *
 * <p>403, and never for a repository the key cannot see or its source may not deliver for — those
 * answer 404, in the words of an absent repository, so a refusal confirms nothing about the estate.
 */
public class ReportImportRefusedException extends RuntimeException {

    public ReportImportRefusedException(String message) {
        super(message);
    }
}
