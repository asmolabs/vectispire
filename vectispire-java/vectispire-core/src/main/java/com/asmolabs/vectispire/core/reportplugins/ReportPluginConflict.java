package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;

/**
 * A report plugin registry's 409, naming its cause: the problem's {@code type} is {@code
 * urn:vectispire:problem:} followed by {@link Cause#token()}, so that a screen tells "somebody else has to
 * approve it" from "it was withdrawn" without parsing a sentence.
 */
public class ReportPluginConflict extends ConflictException {

    private static final long serialVersionUID = 1L;

    /** Why a registry write was refused for the state it found. */
    public enum Cause {
        /** The id is registered already; an id is never reused, since documents in the world name it. */
        ID_TAKEN("report-plugin-id-taken"),
        /** The digest is not the plugin's pending one: approved already, superseded, withdrawn. */
        NOT_PENDING("report-plugin-not-pending"),
        /** Four-eyes is on and the caller registered this digest — somebody else has to approve it. */
        FOUR_EYES("report-plugin-four-eyes"),
        /** The plugin has no approved manifest — pending approval, or withdrawn — so it cannot be switched on. */
        NOT_APPROVED("report-plugin-not-approved"),
        /** The digest was withdrawn: it never runs again, and a fixed image is a new manifest. */
        WITHDRAWN("report-plugin-withdrawn"),
        /** The plugin changed between the read and the write — another governor's gesture; read it again. */
        CHANGED("report-plugin-changed");

        private final String token;

        Cause(String token) {
            this.token = token;
        }

        public String token() {
            return token;
        }
    }

    public ReportPluginConflict(Cause cause, String message) {
        super(message, cause.token());
    }
}
