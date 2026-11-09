package com.asmolabs.vectispire.core.plugins;

/**
 * An import refused for what the caller is or claims, not for the document's form: a session rather
 * than a declared source's key, a key no source is declared for, a tool the source may not deliver.
 *
 * <p>403, and never for a repository the key cannot see or its source may not deliver for — those
 * answer 404, in the words of an absent repository, so a refusal confirms nothing about the estate.
 */
public class SarifImportRefusedException extends RuntimeException {

    public SarifImportRefusedException(String message) {
        super(message);
    }
}
