package com.asmolabs.vectispire.core.rules;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.TriageImpact;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A change of the active rule set that would resolve open issues, and whose caller did not accept
 * exactly that many: 409, with the type {@code urn:vectispire:problem:rule-set-activation-loses-issues}.
 *
 * <p><b>Why a refusal and not a warning.</b> A rule id enters an issue's fingerprint, so a rule
 * that leaves takes its open issues with it at the next scan — the triage, the justifications, the
 * review dates — and nothing errors. The impact preview said so, and activation went ahead whatever
 * it said, or whether anybody had read it. Now the loss is carried out only against its number.
 *
 * <p><b>Equal, not at least.</b> The count is read again in the transaction that activates. A
 * caller naming a number the backlog has since outgrown is refused with the current one, so a
 * preview taken before new findings arrived authorises the loss it showed and no more; a number
 * larger than the loss is refused too, since nobody was shown it.
 *
 * <p>The problem carries the facts of its sentence as members, named as the impact route names
 * them: {@code affectedIssues}, the open issues that would resolve — the number to send back as
 * {@code acceptLosing} — and {@code losingIssues}, the rule identifiers leaving with them.
 */
public final class RuleSetLosesIssuesException extends ConflictException {

    /** The token the problem's {@code type} ends with, published in the routes' descriptions. */
    public static final String CAUSE = "rule-set-activation-loses-issues";

    /** How many rule ids the sentence names before it says how many more; the member names them all. */
    private static final int NAMED_IN_DETAIL = 10;

    private RuleSetLosesIssuesException(String message, TriageImpact impact) {
        super(message, CAUSE, members(impact));
    }

    /**
     * Refuses the change unless it resolves nothing, or the caller accepted exactly what it resolves.
     *
     * @param gesture the sentence's subject — "Activating this rule set"
     */
    static void refuseUnlessAccepted(TriageImpact impact, Long acceptLosing, String gesture) {
        long affected = impact.affectedIssues();
        if (affected == 0 || (acceptLosing != null && acceptLosing == affected)) {
            return;
        }
        List<String> rules = impact.losingIssues();
        String named = String.join(", ", rules.subList(0, Math.min(NAMED_IN_DETAIL, rules.size())))
                + (rules.size() > NAMED_IN_DETAIL ? " and " + (rules.size() - NAMED_IN_DETAIL) + " more" : "");
        String stale = acceptLosing == null
                ? ""
                : " You accepted " + acceptLosing + "; the backlog reads " + affected + " now.";
        throw new RuleSetLosesIssuesException(
                gesture + " resolves " + affected + " open issue(s) at the next scan, with their triage: "
                        + rules.size() + " rule(s) holding them leave — " + named + "." + stale
                        + " Send acceptLosing: " + affected + " to go ahead.",
                impact);
    }

    private static Map<String, Object> members(TriageImpact impact) {
        Map<String, Object> members = new LinkedHashMap<>();
        members.put("affectedIssues", impact.affectedIssues());
        members.put("losingIssues", impact.losingIssues());
        return members;
    }
}
