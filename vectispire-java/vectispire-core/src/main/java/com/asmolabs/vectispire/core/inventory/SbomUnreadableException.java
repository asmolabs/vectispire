package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;

/**
 * A comparison refused because one of its scans' SBOM cannot be read: 409, with the type {@code
 * urn:vectispire:problem:sbom-unreadable}.
 *
 * <p><b>Absent, not empty</b> (decision 0007). The diff swallowed the parse error and compared an empty
 * component list, so an unreadable SBOM came out as "every component removed" — or, against another
 * unreadable one, as "no changes", the answer a reader trusts most and the one nobody had established.
 */
public final class SbomUnreadableException extends ConflictException {

    /** The token the problem's {@code type} ends with. */
    public static final String CAUSE = "sbom-unreadable";

    SbomUnreadableException(long scanId) {
        super("The SBOM of scan " + scanId + " cannot be read, so the two scans are not compared: a comparison "
                + "without it would read as components removed or as no change, neither of which anybody saw.", CAUSE);
    }
}
