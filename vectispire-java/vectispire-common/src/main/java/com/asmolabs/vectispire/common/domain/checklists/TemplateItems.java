package com.asmolabs.vectispire.common.domain.checklists;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The items a confirmed layout reads from its sheet (decision 0032 §3, step 2).
 *
 * <p><b>Filled down, as the sheet means it.</b> The domain and the objective are written on the
 * first row of their group and left blank below, to be read "same as above" — a row's blank domain
 * is the last domain written above it within the item rows, and likewise its objective. When a new
 * domain is written, the objective carried from the previous domain stops: an objective belongs to
 * its domain, and one row of a new domain without its own objective would otherwise inherit a
 * sentence from a group it is not in. A row whose control is empty is not an item — a group's
 * heading row, a spacer — but a domain or objective written on it still carries down.
 */
final class TemplateItems {

    private TemplateItems() {}

    static List<ChecklistItem> read(Workbook workbook, ChecklistLayout layout) {
        Sheet sheet = workbook.sheet(layout.sheet()).orElseThrow(() -> new InvalidTemplateException(
                "The layout names sheet \"" + layout.sheet() + "\", which the workbook does not have."));
        Optional<Integer> id = layout.column(ChecklistColumn.ID);
        Optional<Integer> domainColumn = layout.column(ChecklistColumn.DOMAIN);
        Optional<Integer> objectiveColumn = layout.column(ChecklistColumn.OBJECTIVE);
        int control = layout.column(ChecklistColumn.CONTROL).orElseThrow();
        Optional<Integer> contact = layout.column(ChecklistColumn.CONTACT);
        Optional<Integer> kpi = layout.column(ChecklistColumn.KPI);

        List<ChecklistItem> items = new ArrayList<>();
        String domain = "";
        String objective = "";
        for (int row = layout.firstItemRow(); row <= layout.lastItemRow(); row++) {
            String writtenDomain = text(sheet, domainColumn, row);
            if (!writtenDomain.isBlank() && !writtenDomain.equals(domain)) {
                domain = writtenDomain;
                objective = "";
            }
            String writtenObjective = text(sheet, objectiveColumn, row);
            if (!writtenObjective.isBlank()) {
                objective = writtenObjective;
            }
            String controlText = sheet.text(new CellRef(control, row));
            if (ChecklistText.normalize(controlText).isEmpty()) {
                continue;
            }
            int line = row;
            ItemKey key = id.isPresent()
                    ? keyFromId(sheet.text(new CellRef(id.get(), row)), line)
                    : ItemKey.fromControl(controlText);
            items.add(new ChecklistItem(key, items.size() + 1, domain, objective, controlText, text(sheet, contact, row),
                    text(sheet, kpi, row), row, EvidenceRequirement.NONE, Optional.empty()));
        }
        return items;
    }

    private static ItemKey keyFromId(String id, int row) {
        if (ChecklistText.normalize(id).isEmpty()) {
            throw new InvalidTemplateException("Row " + row + " has a control and no id, and the layout says the id "
                    + "column identifies the items.");
        }
        if (ChecklistText.normalize(id).length() > ItemKey.MAX_ID) {
            throw new InvalidTemplateException("Row " + row + ": the id is longer than " + ItemKey.MAX_ID + " characters.");
        }
        return ItemKey.fromId(id);
    }

    private static String text(Sheet sheet, Optional<Integer> column, int row) {
        return column.map(index -> sheet.text(new CellRef(index, row)).strip()).orElse("");
    }
}
