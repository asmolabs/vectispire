package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerEntity;
import java.time.Instant;

/**
 * One answer to a line, as given: a row of the line's history, never edited (decision 0032 §5).
 *
 * <p>The components are the entity's property names; the account identifiers are left out, the
 * names kept. {@code value} is {@code yes}, {@code no} or {@code not_applicable}. A carried copy keeps
 * the author and instant of the answer it came from ({@code carriedFromId}) and names who carried it,
 * and when; {@code needsConfirmation} marks one carried onto a line that changed, which somebody must
 * answer again or confirm before the revision is submitted. {@code edition} is the revision's edition
 * the row was written at.
 */
public record ChecklistAnswerView(
        Long id,
        Long itemId,
        String value,
        String comment,
        String answeredBy,
        Instant answeredAt,
        Long measurementId,
        Long carriedFromId,
        String carriedBy,
        Instant carriedAt,
        boolean needsConfirmation,
        Integer edition) {

    static ChecklistAnswerView of(ChecklistAnswerEntity row) {
        return new ChecklistAnswerView(row.getId(), row.getItemId(), row.getValue(), row.getComment(),
                row.getAnsweredBy(), row.getAnsweredAt(), row.getMeasurementId(), row.getCarriedFromId(),
                row.getCarriedBy(), row.getCarriedAt(), row.isNeedsConfirmation(), row.getEdition());
    }
}
