package com.asmolabs.vectispire.core.checklists;

import java.util.Locale;

/** What a proof attached to a line is: a link, or an uploaded file ({@code t_checklist_evidence.kind}). */
enum ProofKind {
    LINK,
    FILE;

    String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }
}
