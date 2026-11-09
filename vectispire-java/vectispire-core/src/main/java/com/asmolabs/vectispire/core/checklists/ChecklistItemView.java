package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity;

/**
 * One line of a template version, as the API shows it: the template's words as imported, the key
 * that follows the line into the next version and the digest that says whether what it asks changed.
 *
 * <p>The components are the entity's property names, so that the wire and the table cannot drift
 * apart unnoticed ({@code EntityViewsTest}). {@code evidenceKind} is {@code none}, {@code
 * link_or_file} or {@code file}; {@code boundRule} is the rule the line is measured by (decision 0032
 * §6), or null for a line bound to none — structured, as {@link ChecklistRuleForm}, the shape a checklist
 * line's {@code rule} and the binding route have. It was published as the stored canonical text, which
 * made the one rule two shapes on the wire and left every client to parse JSON out of a string; the text
 * the content digest reads stays in the column, and in the signed {@code checklist.json}.
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
        ChecklistRuleForm boundRule) {

    /** @param rules the stored canonical text of a rule, read as its form */
    static ChecklistItemView of(ChecklistItemEntity item, java.util.function.Function<String, ChecklistRuleForm> rules) {
        return new ChecklistItemView(item.getId(), item.getVersionId(), item.getItemKey(), item.getPosition(),
                item.getDomain(), item.getObjective(), item.getControl(), item.getContact(), item.getKpi(),
                item.getContentDigest(), item.getSheetRow(), item.getEvidenceKind(), item.getEvidenceValidityMonths(),
                item.getBoundRule() == null ? null : rules.apply(item.getBoundRule()));
    }
}
