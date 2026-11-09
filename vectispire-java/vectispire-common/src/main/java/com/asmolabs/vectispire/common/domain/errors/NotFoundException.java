package com.asmolabs.vectispire.common.domain.errors;

import java.util.NoSuchElementException;

/**
 * A row the caller named that is not there — or that is there and not theirs, in the same words.
 *
 * <p><b>Why a type of its own rather than {@link NoSuchElementException}.</b> Every {@code
 * NoSuchElementException} used to answer 404 with its message, and {@code Optional.orElseThrow()}
 * throws one: a lookup that could not fail — the row a service has just written, the setting it has
 * just stored — failed as "No value present", 404, and the defect read as an absence the caller had
 * asked about. Only this type answers 404 with its message now; a bare one is a 500.
 *
 * <p><b>The message is the refusal, whatever the reason.</b> A hidden row and an absent one have to
 * read alike, or the wording confirms what exists (see {@code RowVisibility}); whoever throws this
 * for a visibility check uses the one sentence the absent row gets.
 *
 * <p>Still a {@code NoSuchElementException}, so a caller that catches one keeps catching it.
 */
public class NotFoundException extends NoSuchElementException {

    public NotFoundException(String message) {
        super(message);
    }
}
