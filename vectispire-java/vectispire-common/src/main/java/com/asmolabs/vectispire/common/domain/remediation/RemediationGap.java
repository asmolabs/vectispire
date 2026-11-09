package com.asmolabs.vectispire.common.domain.remediation;

/**
 * A set of open findings that no version bump will close.
 *
 * @param family the token naming the family: the wire name of a
 *     {@link com.asmolabs.vectispire.common.domain.issues.FindingType}, or
 *     {@link RemediationCoverage#UNPACKAGED} for vulnerabilities that name no package. <b>A token
 *     and not a sentence</b>: the sentence explaining how that family is closed is screen text, and
 *     screen text is translated on the client
 * @param findings how many open findings the family holds
 */
public record RemediationGap(String family, long findings) {}
