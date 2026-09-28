package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Locale;
import java.util.Objects;

/**
 * A header entry of the checklist sheet: its label cell, which the renderer leaves alone, and the
 * value cell beside it, which it writes — the product, the author, or the sign-off date.
 */
public record HeaderCell(CellRef label, CellRef value) {

    public HeaderCell {
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(value, "value");
        if (label.equals(value)) {
            throw new InvalidTemplateException("A header's value cell cannot be its label cell, " + label + ".");
        }
    }

    /** The three entries a checklist's header carries (decision 0032 §2). */
    public enum Field {
        /** In a document, the sign-off instant written as a value — never "now", never a formula. */
        DATE,
        /** The project's name. */
        PRODUCT,
        /** The account responsible for the checklist, chosen when it is opened. */
        AUTHOR;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }
}
