package com.asmolabs.vectispire.core.checklists.persistence;

import java.time.Instant;

/**
 * A template version without its workbook: what a listing selects, so that listing ten versions does
 * not read ten files of up to 10 MB each. {@code itemCount} is counted by the same statement.
 */
public record ChecklistTemplateVersionSummary(
        Long id,
        Long templateId,
        Integer ordinal,
        String label,
        String status,
        Integer revision,
        String sourceSha256,
        Long sourceSize,
        String layout,
        boolean offersNotApplicable,
        Long previousVersionId,
        Long derivedFromVersionId,
        String draftAuthors,
        Instant importedAt,
        String importedBy,
        Instant publishedAt,
        String publishedBy,
        Instant retiredAt,
        String retiredBy,
        Long itemCount) {}
