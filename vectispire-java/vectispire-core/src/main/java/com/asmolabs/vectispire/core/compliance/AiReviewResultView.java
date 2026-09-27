package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.aireview.AiReviewStatus;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultEntity;
import java.time.Instant;

/**
 * An OWASP review as the layers above the services hold it: the row's properties under their own
 * names, not the row.
 *
 * <p>{@code prompt} is left out: the route answers with what was reviewed ({@code inputs}) and
 * what came back, and the prompt is this installation's wording, which the report never showed.
 *
 * <p><b>The status is the one the row is in now, not the one it was written with.</b> A review
 * still {@code running} past its deadline was left by a process that stopped before the model
 * answered; it is read as failed, with the reason, from the moment the deadline passes rather than
 * from the hourly sweep that writes it so — an hour of "a report is being written" over a request
 * nobody is serving any more is the silent failure the running state must not introduce.
 */
public record AiReviewResultView(
        Long id,
        Long scanId,
        String model,
        String inputs,
        String response,
        String status,
        String error,
        Instant createdAt,
        Instant deadlineAt) {

    public static AiReviewResultView of(AiReviewResultEntity row, Instant now) {
        boolean abandoned = AiReviewStatus.isAbandoned(row.getStatus(), row.getDeadlineAt(), now);
        return new AiReviewResultView(
                row.getId(),
                row.getScanId(),
                row.getModel(),
                row.getInputs(),
                row.getResponse(),
                abandoned ? AiReviewStatus.FAILED.wireName() : row.getStatus(),
                abandoned ? AiReviewStatus.ABANDONED : row.getError(),
                row.getCreatedAt(),
                row.getDeadlineAt());
    }
}
