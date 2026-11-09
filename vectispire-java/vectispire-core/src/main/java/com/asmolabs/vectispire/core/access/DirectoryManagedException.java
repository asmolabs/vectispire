package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;

/**
 * A change refused because the SCIM directory writes that field of the account: 409, with the type {@code
 * urn:vectispire:problem:managed-by-directory} and the code {@code managed-by-directory}.
 *
 * <p>A 409 rather than a 400: the request is well formed, and the same change succeeds on an account the
 * directory does not provision. It is made in the directory, which replaces the field on its next write —
 * accepting it here would show an address that lasts until the next synchronisation and then vanishes, with
 * nothing to say it had (V102).
 */
public final class DirectoryManagedException extends ConflictException {

    /** The token the problem's {@code type} ends with, published in the route's description. */
    public static final String CAUSE = "managed-by-directory";

    DirectoryManagedException(String username) {
        super("The e-mail address of " + username + " is written by the SCIM directory, which would replace it on "
                + "its next synchronisation: change it in the directory.", CAUSE);
    }
}
