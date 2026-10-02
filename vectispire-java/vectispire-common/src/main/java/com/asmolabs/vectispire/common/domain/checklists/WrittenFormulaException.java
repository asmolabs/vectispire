package com.asmolabs.vectispire.common.domain.checklists;

import java.util.List;

/**
 * A template the renderer cannot fill in because cells it writes carry a formula other cells depend on —
 * the master of a shared formula, or an array formula spanning several cells — with every such cell named,
 * not only the first: a person correcting the workbook corrects them all in one pass.
 *
 * <p>A shared formula keeps its text on its first cell alone; the cells it was filled into carry an index
 * pointing back at it. Writing an answer, a comment or a header value over that first cell takes the text
 * away from all of them, and the workbook a spreadsheet then opens is one it has to repair.
 *
 * @see ChecklistRenderer
 */
public class WrittenFormulaException extends InvalidTemplateException {

    /** The most cells the sentence names one by one; the list carries them all. */
    static final int NAMED = 10;

    private final List<Cell> cells;

    /**
     * One written cell carrying a formula others depend on.
     *
     * @param cell the cell, {@code G7}
     * @param kind {@code shared} or {@code array}, as the workbook's {@code t} attribute names it
     * @param range the cells depending on it, as the workbook's {@code ref} names it
     */
    public record Cell(String cell, String kind, String range) {

        String inWords() {
            return kind.equals("array")
                    ? cell + " (an array formula over " + range + ")"
                    : cell + " (the master of a formula shared across " + range + ")";
        }
    }

    WrittenFormulaException(List<Cell> cells) {
        super(sentence(cells));
        this.cells = List.copyOf(cells);
    }

    public List<Cell> cells() {
        return cells;
    }

    private static String sentence(List<Cell> cells) {
        StringBuilder named = new StringBuilder();
        for (int i = 0; i < Math.min(cells.size(), NAMED); i++) {
            named.append(i == 0 ? "" : ", ").append(cells.get(i).inWords());
        }
        if (cells.size() > NAMED) {
            named.append(" and ").append(cells.size() - NAMED).append(" more");
        }
        boolean one = cells.size() == 1;
        return (one ? "Cell " : "Cells ") + named + " of the checklist sheet " + (one ? "is a cell" : "are cells")
                + " Vectispire writes, and " + (one ? "it holds a formula" : "each holds a formula")
                + " other cells depend on: writing an answer, a comment or a header value there would leave them "
                + "pointing at a formula that is gone. Un-share the formula in the workbook — give each cell its own "
                + "formula, or move it out of the cells the layout writes — and import the workbook again.";
    }
}
