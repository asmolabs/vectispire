package com.asmolabs.zanshin.core.repositories;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

/**
 * A rule set as a listing shows it: everything except the rules themselves.
 *
 * <p>A record rather than the entity with a lazy field. Laziness would put the decision "do
 * not load the files" in a mapping annotation, several files away from the query, and the
 * first caller to touch the getter outside a session would either load the megabytes or throw
 * — depending on configuration nobody reads.
 *
 * @param active {@code true} for the one active set, {@code null} for the others. See {@code
 *     RuleSets} for why it is not {@code false}
 */
public record RuleSetSummary(
        Long id,
        String name,
        String contentHash,
        int ruleCount,
        int fileCount,
        String sizeBytes,
        @JsonProperty("isActive") Boolean active,
        String uploadedBy,
        Instant uploadedAt,
        String activationNote) {}
