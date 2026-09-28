package com.asmolabs.vectispire.common.domain.checklists;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * One version of a template: the file it came from, where its checklist lives in that file, and
 * its items in the sheet's order.
 *
 * <p>Every key is unique within the version — the pairing with the next version would otherwise
 * have two lines to carry one answer onto — and every item sits on a row of the layout's item block,
 * which is where the renderer writes its answer.
 *
 * @param sourceSha256 the workbook's SHA-256, lowercase hex: the renderer writes into that file,
 *     and an auditor compares a delivered document with the template it claims to follow
 */
public record TemplateVersion(String sourceSha256, ChecklistLayout layout, List<ChecklistItem> items) {

    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

    public TemplateVersion {
        Objects.requireNonNull(sourceSha256, "sourceSha256");
        if (!SHA256.matcher(sourceSha256).matches()) {
            throw new IllegalArgumentException("A source digest is 64 lowercase hex digits: " + sourceSha256);
        }
        Objects.requireNonNull(layout, "layout");
        items = List.copyOf(items);
        if (items.isEmpty()) {
            // A version of nothing would be a checklist every project passes by answering nothing.
            throw new InvalidTemplateException("The item rows " + layout.firstItemRow() + " to " + layout.lastItemRow()
                    + " of sheet \"" + layout.sheet() + "\" hold no control: the template has no item.");
        }
        Map<ItemKey, ChecklistItem> byKey = new HashMap<>();
        Map<Integer, ChecklistItem> byRow = new HashMap<>();
        for (int i = 0; i < items.size(); i++) {
            ChecklistItem item = items.get(i);
            if (item.position() != i + 1) {
                throw new IllegalArgumentException("Item " + (i + 1) + " is numbered " + item.position());
            }
            if (item.row() < layout.firstItemRow() || item.row() > layout.lastItemRow()) {
                throw new InvalidTemplateException("Row " + item.row() + " holds an item outside the item rows "
                        + layout.firstItemRow() + " to " + layout.lastItemRow() + ".");
            }
            if (byRow.putIfAbsent(item.row(), item) != null) {
                throw new InvalidTemplateException("Row " + item.row() + " holds two items.");
            }
            ChecklistItem same = byKey.putIfAbsent(item.key(), item);
            if (same != null) {
                throw new InvalidTemplateException("Rows " + same.row() + " and " + item.row() + " read as the same item"
                        + (layout.column(ChecklistColumn.ID).isPresent()
                                ? ": they carry the same id."
                                : ": their controls say the same thing. Name an id column to tell them apart, or "
                                        + "reword one of them."));
            }
        }
    }

    /**
     * The version a confirmed layout reads from a workbook: the item rows, blank domain and objective
     * cells filled down, rows without a control left out.
     *
     * @throws InvalidTemplateException no such sheet, no item, two items with one key, a field too long
     */
    public static TemplateVersion read(Workbook workbook, ChecklistLayout layout) {
        return new TemplateVersion(workbook.sha256(), layout, TemplateItems.read(workbook, layout));
    }
}
