package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.domain.scans.ClassifiedFailure;
import com.asmolabs.vectispire.common.domain.scans.FailureKind;

/**
 * A clone that did not happen — or did not give the scan the tree it needs — with git's own output
 * kept for whoever needs the detail, and what went wrong as a kind.
 *
 * <p><b>The kind decides the scan's fate, the message only informs.</b> A changed host key and a
 * dropped connection both end as a failed clone, and the scan must retry one and not the other; the
 * message is written for a person, scrubbed and cut on its way to the screen, and a rule reading it
 * back would break the day it is reworded — or translated, which is what sent the subprocess version
 * of this class to JGit in the first place. See {@code GitClone.diagnose} for how each kind is told.
 */
public class CloneFailureException extends RuntimeException implements ClassifiedFailure {

    /** What stopped the clone, each with what another attempt could change. */
    public enum Kind {
        /** The server's host key is not the one recorded or pinned for it. */
        HOST_KEY(FailureKind.PERMANENT),
        /** The forge refused the credential, or asked for one and none was given — SSH or HTTPS. */
        AUTHENTICATION(FailureKind.PERMANENT),
        /** The forge says the repository does not exist, or is not this credential's to see. */
        NOT_FOUND(FailureKind.PERMANENT),
        /** The repository exists and the branch the scan names does not. */
        BRANCH_ABSENT(FailureKind.PERMANENT),
        /** The credential this executor holds cannot be used: a key that does not parse, a token bound to another host. */
        CREDENTIAL(FailureKind.PERMANENT),
        /** The clone's own guard refused where the URL leads: its form, a link-local host, a redirect. */
        URL_REFUSED(FailureKind.PERMANENT),
        /** The clone holds no directory at the repository's sub-path, or the sub-path leads out of it. */
        SUB_PATH(FailureKind.PERMANENT),
        /** The forge did not answer in time. */
        TIMEOUT(FailureKind.TRANSIENT),
        /** The host could not be reached: no route, no name, a refused or reset connection. */
        NETWORK(FailureKind.TRANSIENT),
        /** The forge answered with an error of its own — a 5xx, a 429. */
        UNAVAILABLE(FailureKind.TRANSIENT),
        /** Nothing typed says which: transient, as every failure is when in doubt. */
        UNCLASSIFIED(FailureKind.TRANSIENT);

        private final FailureKind failureKind;

        Kind(FailureKind failureKind) {
            this.failureKind = failureKind;
        }

        public FailureKind failureKind() {
            return failureKind;
        }
    }

    private final Kind kind;
    private final String stderr;

    CloneFailureException(Kind kind, String message, String stderr) {
        super(message);
        this.kind = kind;
        this.stderr = stderr == null ? "" : stderr;
    }

    public Kind kind() {
        return kind;
    }

    @Override
    public FailureKind failureKind() {
        return kind.failureKind();
    }

    public String stderr() {
        return stderr;
    }
}
