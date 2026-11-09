package com.asmolabs.vectispire.core.checklists;

import java.time.Instant;
import java.util.List;

/**
 * A template version without its items: where it stands and who moved it there.
 *
 * @param status {@code draft}, {@code published} or {@code retired}
 * @param revision the draft's edit counter; publishing names the revision the publisher reviewed,
 *     and a draft edited since is refused rather than published unseen
 * @param layoutConfirmed whether a person has confirmed a layout — a draft without one has no item
 *     and cannot be published
 * @param previousOrdinal the version its items are paired with, when there is one
 * @param derivedFromOrdinal the published version it was derived from, when it was derived
 * @param draftAuthors the accounts that wrote it — imported or derived it, confirmed its layout,
 *     paired its items. With four-eyes on, none of them may publish or retire it
 */
public record ChecklistVersionSummary(
        Long id,
        int ordinal,
        String label,
        String status,
        int revision,
        String sourceSha256,
        long sourceSize,
        boolean layoutConfirmed,
        boolean offersNotApplicable,
        long itemCount,
        Integer previousOrdinal,
        Integer derivedFromOrdinal,
        List<String> draftAuthors,
        Instant importedAt,
        String importedBy,
        Instant publishedAt,
        String publishedBy,
        Instant retiredAt,
        String retiredBy) {}
