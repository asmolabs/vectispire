package com.asmolabs.vectispire.core.checklists;

import java.time.Instant;
import java.time.LocalDate;

/**
 * A proof attached to a line (decision 0032 §5): a link, or a file named by its name, size and SHA-256
 * — its bytes only through the download route, as an attachment.
 *
 * @param kind {@code link} or {@code file}
 * @param mediaType as the uploader declared it; shown, never used to decide how the file is served
 * @param performedOn the day the work it proves was done
 * @param validUntil the last day it holds, for a line that says how long a proof holds; null otherwise
 * @param inDate whether it holds today: not withdrawn, and not past {@code validUntil}
 * @param carriedFromId the proof of the previous revision this one was carried from, when it was
 */
public record ChecklistEvidenceView(
        Long id,
        Long itemId,
        String kind,
        String link,
        String fileName,
        String mediaType,
        Long fileSize,
        String fileSha256,
        LocalDate performedOn,
        LocalDate validUntil,
        String addedBy,
        Instant addedAt,
        Long carriedFromId,
        Integer edition,
        String withdrawnBy,
        Instant withdrawnAt,
        boolean inDate) {}
