package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;

/**
 * A checklist template refused — the workbook, its layout, or the version read from them — with a
 * reason meant for the person importing it.
 *
 * <p>An {@link InvalidInputException}, so the import route answers 400 in these words without a
 * mapping of its own: the file and the layout are the importer's, and the importer can correct
 * both. Every sentence names the part, the cell or the row it is about, because a workbook has no
 * line numbers anybody can see.
 */
public class InvalidTemplateException extends InvalidInputException {

    public InvalidTemplateException(String message) {
        super(message);
    }
}
