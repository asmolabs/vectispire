package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import java.util.List;
import java.util.Map;

/**
 * A checklist's 409 — a project checklist's or a template version's — naming its cause: the problem's
 * {@code type} is {@code urn:vectispire:problem:} followed by {@link Cause#token()}.
 *
 * <p><b>Why each cause is named.</b> The template routes answered one 409 for "changed since you read
 * it", "not a draft" and "four-eyes", and a screen could only show the sentence: it could not offer to
 * reload for the first, nor say "somebody else must sign" for the last, without parsing words that
 * change with their wording. Every checklist write can meet several of these; each is its own token —
 * the template routes' included, since the lot after the project checklists: they had kept the one
 * bare 409 the causes were invented to end.
 *
 * <p><b>One convention for both halves of the module.</b> The template versions' causes are {@code
 * checklist-template-…}, apart from the project checklists' ones, because the gesture differs even
 * where the words match: a template version that is not a draft is derived from, a checklist revision
 * that is not a draft is returned; a template read again is named by its {@code revision}, a checklist
 * by its {@code edition}. One token is shared, {@code checklist-four-eyes}: on both it means exactly
 * "four-eyes is on and you wrote this — somebody else has to do it".
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
        /**
         * Four-eyes is on and the caller wrote what it is signing off, publishing or retiring — a
         * checklist revision's author, or a template version's.
         */
        FOUR_EYES("checklist-four-eyes"),
        /** A checklist opens on a published version only — not a draft, not a retired one. */
        VERSION_NOT_PUBLISHED("checklist-version-not-published"),
        /** The project's checklist is already on that version. */
        SAME_VERSION("checklist-same-version"),
        /** The line's answer is not a carried one awaiting confirmation. */
        NOTHING_TO_CONFIRM("checklist-nothing-to-confirm"),
        /** The proof is already withdrawn. */
        EVIDENCE_WITHDRAWN("checklist-evidence-withdrawn"),
        /**
         * A line is answered "yes" where its measurement fails (decision 0032, question 3): refused at
         * submission — a false positive is settled by triage, a rule the organisation disagrees with is
         * changed in a new version, visibly.
         */
        MEASUREMENT_CONTRADICTED("checklist-measurement-contradicted"),
        /**
         * A line's measurement is not what it was when the person read it — at the sign-off, not what it
         * was at the submission; for an answer resting on a measurement, not the one the person saw. A
         * signature must not attest to evidence that stopped being true in between.
         */
        MEASUREMENT_CHANGED("checklist-measurement-changed"),

        // The template versions' causes (decision 0032 §3, §4, §8).

        /** Only a draft version is edited or published; this one is published or retired — derive a new one. */
        TEMPLATE_NOT_DRAFT("checklist-template-not-draft"),
        /** The draft's layout is not confirmed, so it has no item: confirm it first. */
        TEMPLATE_NO_LAYOUT("checklist-template-no-layout"),
        /** The version changed since the revision the writer read — edited, published or retired. */
        TEMPLATE_CHANGED("checklist-template-changed"),
        /** The template already has a draft: one at a time, published or set aside before another. */
        TEMPLATE_HAS_DRAFT("checklist-template-has-draft"),
        /** A new version is derived from a published one, and this one is a draft or retired. */
        TEMPLATE_NOT_PUBLISHED("checklist-template-not-published"),
        /** The version is already retired. */
        TEMPLATE_RETIRED("checklist-template-retired"),
        /** The draft follows no published version, so there is nothing to pair its items with. */
        TEMPLATE_NOTHING_TO_PAIR("checklist-template-nothing-to-pair");

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

    /**
     * A {@link Cause#INCOMPLETE} refusal naming its lines as data too, in the problem's {@code lines}
     * member: each line's item, position and problems — the tokens a line's view carries — so that a
     * client points at them in its own language rather than parsing the English sentence.
     */
    static ChecklistConflict incomplete(String message, List<IncompleteLine> lines) {
        return new ChecklistConflict(Cause.INCOMPLETE, message, Map.of("lines", List.copyOf(lines)));
    }

    private ChecklistConflict(Cause reason, String message, Map<String, ?> members) {
        super(message, reason.token(), members);
        this.reason = reason;
    }

    /**
     * A {@link Cause#MEASUREMENT_CONTRADICTED} or {@link Cause#MEASUREMENT_CHANGED} refusal naming its
     * lines as data too, in the problem's {@code lines} member.
     */
    static ChecklistConflict measured(Cause cause, String message, List<MeasuredLine> lines) {
        return new ChecklistConflict(cause, message, Map.of("lines", List.copyOf(lines)));
    }

    /**
     * One line whose measurement refused a submission or a sign-off, as the problem's {@code lines}
     * member states it.
     *
     * @param answer the line's current answer, {@code yes}, {@code no} or {@code not_applicable}; null
     *     when it has none
     * @param outcome and {@code reason}: what the rule finds now
     * @param submittedOutcome and {@code submittedReason}: what it found at the submission, for a
     *     sign-off's refusal; null otherwise, and null when the submission measured nothing
     */
    public record MeasuredLine(long itemId, int position, String answer, String outcome, String reason,
            String submittedOutcome, String submittedReason) {}

    /**
     * One line keeping a revision from a submission or a sign-off, as the problem's {@code lines} member
     * states it.
     *
     * @param itemId the template item the line answers — what the line's routes name
     * @param problems {@code unanswered}, {@code awaiting_confirmation}, {@code comment_required}, {@code
     *     evidence_required}, {@code evidence_expired}, as a line's view names them — never {@code
     *     measurement_contradicted}, which refuses under a cause of its own
     */
    public record IncompleteLine(long itemId, int position, List<String> problems) {

        public IncompleteLine {
            problems = List.copyOf(problems);
        }
    }

    public Cause reason() {
        return reason;
    }
}
