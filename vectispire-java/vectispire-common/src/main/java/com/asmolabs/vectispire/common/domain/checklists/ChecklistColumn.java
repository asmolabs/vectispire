package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Locale;

/** The columns of a checklist sheet a layout can name. */
public enum ChecklistColumn {
    /** The organisation's own identifier of a line, when the template has one: it becomes the key. */
    ID(false),
    DOMAIN(false),
    OBJECTIVE(false),
    CONTROL(true),
    CONTACT(false),
    KPI(false),
    ANSWER(true),
    /** Required: a negative answer needs its comment, and the renderer needs a cell to write it in. */
    COMMENT(true);

    private final boolean required;

    ChecklistColumn(boolean required) {
        this.required = required;
    }

    /** Without it no item can be read or no answer written. */
    public boolean required() {
        return required;
    }

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }
}
