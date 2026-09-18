package com.asmolabs.vectispire.common.domain.attackpath;

import java.util.List;
import java.util.Map;

/**
 * A concrete end-to-end attack scenario from external exposure to asset compromise.
 */
public record AttackPath(
        String id,
        Scenario scenario,
        Map<String, String> params,
        String riskLevel,
        boolean isDirectlyExploitable,
        List<String> nodeIds) {

    /**
     * Which scenario this is; the title, the narrative and the remediation steps follow from it.
     *
     * <p><b>One token in place of three sentences</b>, for the reason {@code RemediationGap}
     * states. The three used to be built by concatenation on the server — a method, a path and a
     * package name glued into French prose — and the screen printed them as they stood. A
     * concatenation cannot be reordered by a translator, which is why the values that varied now
     * travel beside the token rather than inside the sentence.
     */
    public enum Scenario {
        /** An unauthenticated endpoint reaching a vulnerable component, reaching the data store. */
        UNAUTH_RCE_CHAIN,
        PLAINTEXT_SECRET,
        /** Nothing chains together — stated rather than left as an empty list. */
        NO_CRITICAL_PATH
    }
}
