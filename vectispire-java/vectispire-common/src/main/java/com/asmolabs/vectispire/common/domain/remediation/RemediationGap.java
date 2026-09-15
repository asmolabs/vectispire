package com.asmolabs.vectispire.common.domain.remediation;

/**
 * Un ensemble de constats ouverts qu'aucune montée de version ne fermera.
 *
 * @param family le jeton qui nomme la famille : le nom de transport d'un
 *     {@link com.asmolabs.vectispire.common.domain.issues.FindingType}, ou
 *     {@link RemediationCoverage#UNPACKAGED} pour les vulnérabilités dont aucun paquet n'est
 *     nommé. <b>Un jeton et non une phrase</b> : la phrase qui explique comment on referme cette
 *     famille-là est du texte d'écran, et le texte d'écran est traduit côté client
 * @param findings combien de constats ouverts la famille compte
 */
public record RemediationGap(String family, long findings) {}
