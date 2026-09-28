package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;

/**
 * A project checklist's 409, naming its cause — the problem's {@code type} is {@code
 * urn:vectispire:problem:} followed by {@link Cause#token()}.
 *
 * <p><b>Why each cause is named.</b> The template routes answered one 409 for "changed since you read
 * it", "not a draft" and "four-eyes", and a screen could only show the sentence: it could not offer to
 * reload for the first, nor say "somebody else must sign" for the last, without parsing words that
 * change with their wording. Every checklist write can meet several of these; each is its own token.
 */
public class ChecklistConflict extends ConflictException {

    /** Why a checklist write was refused for the state it found. */
    public enum Cause {
        /** The revision changed since the edition the writer read — read it again. */
        CHANGED("checklist-changed"),
        /** The line changed since the edition the writer read — an answer or a proof by somebody else. */
        LINE_CHANGED("checklist-line-changed"),
        /** Only a draft is answered, proven or submitted; this one is submitted, signed off or superseded. */
        NOT_DRAFT("checklist-not-draft"),
        /** Only a submitted revision is signed off or returned. */
        NOT_SUBMITTED("checklist-not-submitted"),
        /** Only a signed-off revision is reopened. */
        NOT_SIGNED_OFF("checklist-not-signed-off"),
        /** A newer revision of the project's checklist exists; act on that one. */
        NOT_LATEST("checklist-not-latest"),
        /** A line is unanswered, uncommented, unproven, its proof out of date, or awaiting confirmation. */
        INCOMPLETE("checklist-incomplete"),
        /** Four-eyes is on and the signer is one of the revision's authors. */
        FOUR_EYES("checklist-four-eyes"),
        /** A checklist opens on a published version only — not a draft, not a retired one. */
        VERSION_NOT_PUBLISHED("checklist-version-not-published"),
        /** The project's checklist is already on that version. */
        SAME_VERSION("checklist-same-version"),
        /** The line's answer is not a carried one awaiting confirmation. */
        NOTHING_TO_CONFIRM("checklist-nothing-to-confirm"),
        /** The proof is already withdrawn. */
        EVIDENCE_WITHDRAWN("checklist-evidence-withdrawn");

        private final String token;

        Cause(String token) {
            this.token = token;
        }

        public String token() {
            return token;
        }
    }

    private final Cause reason;

    public ChecklistConflict(Cause reason, String message) {
        super(message, reason.token());
        this.reason = reason;
    }

    public Cause reason() {
        return reason;
    }
}
