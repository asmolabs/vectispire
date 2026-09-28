package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity;

/**
 * One line of a template version, as the API shows it: the template's words as imported, the key
 * that follows the line into the next version and the digest that says whether what it asks changed.
 *
 * <p>The components are the entity's property names, so that the wire and the table cannot drift
 * apart unnoticed ({@code EntityViewsTest}). {@code evidenceKind} is {@code none}, {@code
 * link_or_file} or {@code file}; {@code boundRule} is null until a later lot binds rules (decision
 * 0032 §6).
 */
public record ChecklistItemView(
        Long id,
        Long versionId,
        String itemKey,
        Integer position,
        String domain,
        String objective,
        String control,
        String contact,
        String kpi,
        String contentDigest,
        Integer sheetRow,
        String evidenceKind,
        Integer evidenceValidityMonths,
        String boundRule) {

    static ChecklistItemView of(ChecklistItemEntity item) {
        return new ChecklistItemView(item.getId(), item.getVersionId(), item.getItemKey(), item.getPosition(),
                item.getDomain(), item.getObjective(), item.getControl(), item.getContact(), item.getKpi(),
                item.getContentDigest(), item.getSheetRow(), item.getEvidenceKind(), item.getEvidenceValidityMonths(),
                item.getBoundRule());
    }
}
