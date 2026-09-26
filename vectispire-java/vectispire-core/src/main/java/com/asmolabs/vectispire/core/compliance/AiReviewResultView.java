package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultEntity;
import java.time.Instant;

/**
 * An OWASP review as the layers above the services hold it: the row's properties under their own
 * names, not the row.
 *
 * <p>{@code prompt} is left out: the route answers with what was reviewed ({@code inputs}) and
 * what came back, and the prompt is this installation's wording, which the report never showed.
 */
public record AiReviewResultView(
        Long id,
        Long scanId,
        String model,
        String inputs,
        String response,
        String status,
        String error,
        Instant createdAt) {

    public static AiReviewResultView of(AiReviewResultEntity row) {
        return new AiReviewResultView(
                row.getId(),
                row.getScanId(),
                row.getModel(),
                row.getInputs(),
                row.getResponse(),
                row.getStatus(),
                row.getError(),
                row.getCreatedAt());
    }
}
