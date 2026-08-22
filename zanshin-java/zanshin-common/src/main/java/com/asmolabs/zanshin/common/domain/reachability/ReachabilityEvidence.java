package com.asmolabs.zanshin.common.domain.reachability;

/**
 * Concrete call-site evidence demonstrating reachability of a vulnerable dependency.
 */
public record ReachabilityEvidence(
        String symbol,
        String sourceFile,
        int lineNumber,
        String snippet) {}
