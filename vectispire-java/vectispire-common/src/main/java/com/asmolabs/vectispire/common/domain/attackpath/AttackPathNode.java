package com.asmolabs.vectispire.common.domain.attackpath;

import java.util.Map;

/**
 * An individual entity in an attack chain (Ingress, API endpoint, vulnerable dependency, secret, or database).
 */
public record AttackPathNode(
        String id,
        String label,
        AttackPathNodeType type,
        String severity,
        boolean isExploitable,
        NodeNote note,
        Map<String, String> metadata) {

    /**
     * What a node is, said as a token the graph screen translates.
     *
     * <p><b>A token and not a sentence</b>, for the reason {@code RemediationGap} states. This
     * field carried French prose — "Route Non-Authentifiée", "Clé API / Mot de passe dans le
     * code" — drawn straight onto a graph whose surrounding interface follows the reader's
     * language.
     *
     * <p>The four vulnerability notes are a pair of booleans flattened into constants rather than
     * two fields: they were assembled by string concatenation on the server, and a concatenation
     * is exactly what a translation cannot reorder.
     */
    public enum NodeNote {
        PUBLIC_INGRESS,
        UNAUTHENTICATED_ROUTE,
        AUTHENTICATED_PUBLIC_ROUTE,
        /** Remote code execution, and listed in the CISA KEV catalogue. */
        RCE_ACTIVELY_EXPLOITED,
        RCE_EXECUTABLE,
        ACTIVELY_EXPLOITED,
        EXECUTABLE,
        SENSITIVE_DATA_STORE,
        HARDCODED_CREDENTIAL
    }
}
