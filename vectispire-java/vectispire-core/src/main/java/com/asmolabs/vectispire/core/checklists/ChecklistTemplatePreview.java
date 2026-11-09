package com.asmolabs.vectispire.core.checklists;

import java.util.List;
import java.util.Map;

/**
 * What the importer looks at before confirming a draft (decision 0032 §3): what the reader proposes,
 * what has been confirmed, the sheet itself, and how the items pair with the previous version.
 *
 * <p>The proposal is only ever a proposal — found from the workbook's structure, never from its
 * words — and nothing reads it but the person confirming. What the renderer reads is {@code layout},
 * once somebody has confirmed it.
 *
 * @param sheets the workbook's sheets, in its order
 * @param sheet the sheet {@code cells} are read from: the one asked for, else the confirmed layout's,
 *     else the proposal's
 * @param cells the sheet's cells that hold something, in reading order, at most {@value
 *     ChecklistTemplateService#PREVIEW_CELLS}; {@code cellsTruncated} says when there were more
 * @param layout the confirmed layout, or null
 * @param pairing each item's fate against the previous version, the new version's in its order then
 *     the removed ones; empty until a layout is confirmed. With no previous version, every item is
 *     {@code added}
 */
public record ChecklistTemplatePreview(
        String templateSlug,
        ChecklistVersionSummary version,
        List<String> sheets,
        String sheet,
        List<PreviewCell> cells,
        boolean cellsTruncated,
        ProposedLayout proposal,
        ChecklistLayoutForm layout,
        List<PairingChange> pairing) {

    /**
     * One cell of the sheet as the reader sees it.
     *
     * @param formula whether the cell holds a formula — a date recalculated at every opening does,
     *     and the renderer will replace it with the sign-off instant
     */
    public record PreviewCell(String ref, int row, String column, String text, boolean formula) {}

    /**
     * Where the reader thinks the checklist is — any part it could not find left out, for the
     * importer to name.
     *
     * @param answerValues the values of the answer column's validation list, offered for mapping to
     *     yes, no and not applicable; empty when the list is not one the reader can read
     */
    public record ProposedLayout(
            String sheet,
            Integer columnHeaderRow,
            Integer firstItemRow,
            Integer lastItemRow,
            Map<String, String> columns,
            Map<String, ChecklistLayoutForm.HeaderCellForm> header,
            List<String> answerValues) {}

    /**
     * What became of one item between the previous version and this one.
     *
     * @param change {@code unchanged}, {@code changed}, {@code added} or {@code removed}
     * @param pairedByHand the importer said these two are one control; the item carries the old key
     * @param readKey the new item's key as the layout read it — what a pair names as {@code added}
     * @param previousKey the previous version's key — what a pair names as {@code removed}
     */
    public record PairingChange(
            String change,
            boolean pairedByHand,
            String readKey,
            Integer row,
            String control,
            String previousKey,
            Integer previousRow,
            String previousControl) {}
}
