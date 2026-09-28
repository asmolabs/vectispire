package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.util.Locale;
import java.util.Objects;

/**
 * What identifies an item across the versions of its template, so that an answer can follow it.
 *
 * <p>From the id column when the layout names one — the organisation's own identifier, kept as
 * written (normalised). Otherwise from the control's text, since a template like the first one has
 * nothing else that identifies a line (decision 0032, "nothing identifies a control but its
 * text"). A row number is never it: a row moves when a line is inserted above.
 *
 * <p><b>A derived key is folded to lower case on top of {@link ChecklistText}</b>, and the content
 * digest is not: a control whose only change is a capital keeps its key and changes its digest, so
 * it pairs as <em>changed</em> — its answer carried, to be confirmed — rather than as one line
 * removed and another added, whose answer nobody would carry. The two prefixes keep a key from an id
 * column from ever equalling a derived one.
 *
 * <p>A data contract: stored with the item, compared with the next version's. Changing how it is
 * derived unpairs every template.
 */
public record ItemKey(String value) {

    public static final int MAX_ID = 200;
    private static final String FROM_ID = "id:";
    private static final String FROM_TEXT = "text:";

    public ItemKey {
        Objects.requireNonNull(value, "value");
        if (!value.startsWith(FROM_ID) && !value.startsWith(FROM_TEXT)) {
            throw new IllegalArgumentException("An item key is derived by fromId or fromControl, not written: " + value);
        }
    }

    /** @throws InvalidInputException a blank id, or one past {@value #MAX_ID} characters */
    public static ItemKey fromId(String id) {
        String normalized = ChecklistText.normalize(id);
        if (normalized.isEmpty()) {
            throw new InvalidInputException("The item's id is blank.");
        }
        if (normalized.length() > MAX_ID) {
            throw new InvalidInputException("The item's id is longer than " + MAX_ID + " characters.");
        }
        return new ItemKey(FROM_ID + normalized);
    }

    /** @throws InvalidInputException a blank control, which is not an item */
    public static ItemKey fromControl(String control) {
        String normalized = ChecklistText.normalize(control);
        if (normalized.isEmpty()) {
            throw new InvalidInputException("The item's control is blank.");
        }
        return new ItemKey(FROM_TEXT + Digests.sha256Hex(normalized.toLowerCase(Locale.ROOT)));
    }
}
