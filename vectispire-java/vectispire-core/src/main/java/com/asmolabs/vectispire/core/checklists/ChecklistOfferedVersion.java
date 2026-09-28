package com.asmolabs.vectispire.core.checklists;

import java.time.Instant;

/**
 * A published template version a project's checklist may be opened on or moved to — what the person
 * opening one picks from, without the governance reading the templates' own routes require.
 */
public record ChecklistOfferedVersion(
        String templateSlug,
        String templateName,
        int ordinal,
        String label,
        long itemCount,
        boolean offersNotApplicable,
        Instant publishedAt) {}
