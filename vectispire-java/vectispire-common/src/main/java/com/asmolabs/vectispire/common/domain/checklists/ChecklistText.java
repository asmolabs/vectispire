package com.asmolabs.vectispire.common.domain.checklists;

import java.text.Normalizer;
import java.util.regex.Pattern;

/**
 * The one normalisation a template's words go through before they identify or fingerprint an item.
 *
 * <p><b>A data contract, like an issue's fingerprint.</b> An item's key and its content digest are
 * computed over this form and stored; change a step here and every stored key stops matching the
 * one computed for the same words, so the next version pairs nothing — every item reads as removed
 * and re-added, and every answer carried across it as a new line to answer from scratch. Add a step
 * only with a migration that recomputes the stored forms.
 *
 * <p>What it absorbs is what a workbook changes without anybody changing the words: NFKC, so a
 * ligature or a full-width digit reads as its plain form; every run of whitespace — a line break
 * inside a cell, a non-breaking space pasted from a document — as one space; zero-width and other
 * format characters removed; the ends trimmed. It keeps case: a capital is a change of wording the
 * digest should see (the key, which pairs, is folded on top of this; see {@link ItemKey}).
 */
public final class ChecklistText {

    private static final Pattern FORMAT = Pattern.compile("\\p{Cf}");
    private static final Pattern SPACES = Pattern.compile("[\\p{javaWhitespace}\\p{Z}\\p{Cc}]+");

    private ChecklistText() {}

    /** The normalised form; {@code null} reads as the empty string, the same as a blank cell. */
    public static String normalize(String value) {
        if (value == null) {
            return "";
        }
        String composed = Normalizer.normalize(value, Normalizer.Form.NFKC);
        return SPACES.matcher(FORMAT.matcher(composed).replaceAll("")).replaceAll(" ").strip();
    }
}
