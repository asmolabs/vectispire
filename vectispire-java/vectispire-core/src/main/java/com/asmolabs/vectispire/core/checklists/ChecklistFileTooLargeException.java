package com.asmolabs.vectispire.core.checklists;

/**
 * An uploaded proof past its ceiling, found by the service — the body filter refuses a declared length
 * first; this is the same limit, held where the bytes are stored. Answered 413.
 */
public class ChecklistFileTooLargeException extends RuntimeException {

    public ChecklistFileTooLargeException(long ceiling) {
        super("A proof is at most " + ceiling + " bytes; attach a larger document as a link.");
    }
}
