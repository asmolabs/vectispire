package com.asmolabs.vectispire.common.domain.sarif;

import com.asmolabs.vectispire.common.domain.issues.Severity;

/**
 * One result of a SARIF run, reduced to what Vectispire keeps.
 *
 * @param ruleId enters the issue's fingerprint, whole: a tool that renames a rule loses the triage
 *     attached to it, and nothing on this side can tell a rename from a new rule
 * @param file relative to the analysed tree, normalised by {@link SarifPaths} — also a fingerprint
 *     input; {@code null} for a result that names no file
 * @param line the first line of the region, or {@code null}; never in the fingerprint
 * @param message what the tool said, for the backlog's description
 */
public record SarifFinding(String ruleId, Severity severity, String file, Integer line, String message) {}
