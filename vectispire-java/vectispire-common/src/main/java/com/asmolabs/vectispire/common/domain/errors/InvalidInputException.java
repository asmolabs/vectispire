package com.asmolabs.vectispire.common.domain.errors;

/**
 * A value the caller supplied and can correct, refused with a sentence written for them.
 *
 * <p><b>Why a type of its own rather than {@link IllegalArgumentException}.</b> Every {@code
 * IllegalArgumentException} used to answer 400 with its message, so the refusals written for an
 * operator ("Scheme "ftp" is not allowed…") and the ones nobody wrote for anybody — Spring Data's
 * "The given id must not be null", a JDK parser's "For input string" — reached the client alike: a
 * library's internals on the wire, and a programming error reported as the caller's mistake. Only
 * this type answers 400 with its message now; a bare {@code IllegalArgumentException} is a 500 with a
 * generic sentence and a correlation id in the log.
 *
 * <p><b>Still an {@code IllegalArgumentException}</b>, so the code that catches one to turn a
 * refusal into an outcome — a SARIF step failing absent, a setting reported invalid — keeps catching
 * it without being rewritten.
 */
public class InvalidInputException extends IllegalArgumentException {

    public InvalidInputException(String message) {
        super(message);
    }

    public InvalidInputException(String message, Throwable cause) {
        super(message, cause);
    }
}
