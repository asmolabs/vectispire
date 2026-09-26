package com.asmolabs.vectispire.core.rules.persistence;

import java.time.Instant;

/**
 * A rule set as the listing query selects it: everything except the rules themselves.
 *
 * <p><b>Not what the listing sends.</b> It was, under the name {@code RuleSetSummary}, from the day
 * it sat in {@code core.repositories}: a projection of the table on the wire, which the rule keeping
 * entities off routes never read because it is not an entity. The route now answers {@link
 * com.asmolabs.vectispire.core.rules.RuleSetSummary}, whose components and JSON names are these —
 * so a column renamed here fails to compile in {@code RuleSetService} instead of renaming a field
 * of the contract (decision 0029).
 *
 * <p>A record rather than the entity with a lazy field. Laziness would put the decision "do
 * not load the files" in a mapping annotation, several files away from the query, and the
 * first caller to touch the getter outside a session would either load the megabytes or throw
 * — depending on configuration nobody reads.
 *
 * @param active {@code true} for the one active set, {@code null} for the others. See {@code
 *     RuleSets} for why it is not {@code false}
 */
public record RuleSetRow(
        Long id,
        String name,
        String contentHash,
        int ruleCount,
        int fileCount,
        String sizeBytes,
        Boolean active,
        String uploadedBy,
        Instant uploadedAt,
        String activationNote) {}
