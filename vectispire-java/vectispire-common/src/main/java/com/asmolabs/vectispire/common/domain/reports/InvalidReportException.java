package com.asmolabs.vectispire.common.domain.reports;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;

/**
 * A coverage or test report refused, with a reason meant for the pipeline that produced it.
 *
 * <p>An {@link InvalidInputException}, so an import route answers 400 in these words without a
 * mapping of its own — the document is the caller's, and the caller can fix it. The same type for a
 * body that does not read as the declared format and for one that reads but states nothing: both
 * are the pipeline's to correct, and neither may be recorded (decision 0007).
 */
public class InvalidReportException extends InvalidInputException {

    public InvalidReportException(String message) {
        super(message);
    }
}
