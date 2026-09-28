package com.asmolabs.vectispire.core.checklists;

import java.util.List;

/**
 * One template version whole: where it stands, its confirmed layout, its items in the sheet's order,
 * and the pairs made by hand with the previous version.
 *
 * @param layout null until a person has confirmed one
 * @param pairs each {@code added} key — the item as the layout read it — is the {@code removed} key
 *     of the previous version, reworded; the item is stored under the removed one
 */
public record ChecklistVersionView(
        String templateSlug,
        String templateName,
        ChecklistVersionSummary version,
        ChecklistLayoutForm layout,
        List<ChecklistItemView> items,
        List<ChecklistItemPair> pairs) {}
