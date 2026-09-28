package com.asmolabs.vectispire.core.checklists;

import java.time.Instant;
import java.util.List;

/** A checklist template and its versions, oldest first, without their items. */
public record ChecklistTemplateView(
        Long id,
        String slug,
        String name,
        Instant createdAt,
        String createdBy,
        List<ChecklistVersionSummary> versions) {}
