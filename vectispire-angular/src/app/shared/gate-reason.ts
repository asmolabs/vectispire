import type { I18nService } from '../core/i18n/i18n.service';
import { keyFor } from '../core/i18n/literal-keys';
import type { GateViolation, Observation } from '../core/api.models';
import { severityLabel } from './severity';

/**
 * A gate violation's reason, in the reader's language (decision 0019).
 *
 * **The screens printed the server's sentence**, which is English: a French reader was told why their
 * build stopped in a language the rest of the screen does not speak. The violation carries `rule`, a
 * token, and the values the sentence is made of (`severity`, `identifier`), so the sentence is written
 * here from those — and `reason` stays what an English pipeline log quotes.
 *
 * **Two values are not fields of the violation**: the policy's threshold, for `severity`, and the
 * uncovered ecosystems, for `coverage`. The translated sentence does not name them rather than parse
 * them out of English; the screens keep the server's sentence as the line's tooltip, so they are one
 * hover away and never lost.
 *
 * A rule this client does not know is shown in the server's words — enum values are open (decision
 * 0043 §1), and a newer server's rule must not read as one of these.
 */
export const RULE_SENTENCE_KEYS = {
    kev: 'gate_reason.kev',
    severity: 'gate_reason.severity',
    coverage: 'gate_reason.coverage',
    observation: 'gate_reason.observation'
} as const satisfies Record<GateViolation['rule'], string>;

/** `observation` names which examination is missing when the screen knows the target's observation. */
export const OBSERVATION_SENTENCE_KEYS = {
    never_scanned: 'gate_reason.never_scanned',
    last_scan_failed: 'gate_reason.last_scan_failed',
    in_progress: 'gate_reason.in_progress'
} as const satisfies Record<Exclude<Observation, 'ok'>, string>;

export function gateReason(
    i18n: Pick<I18nService, 't'>,
    violation: Pick<GateViolation, 'rule' | 'severity' | 'reason'>,
    observation?: Observation | null
): string {
    const key = keyFor(RULE_SENTENCE_KEYS, violation.rule);
    if (!key) return violation.reason;
    if (violation.rule === 'observation') {
        const precise = keyFor(OBSERVATION_SENTENCE_KEYS, observation);
        return i18n.t(precise ?? key);
    }
    if (violation.rule === 'severity') {
        // Without the severity there is nothing to say that the server's sentence does not say better.
        if (!violation.severity) return violation.reason;
        return i18n.t(key, { severity: severityLabel(i18n, violation.severity) });
    }
    return i18n.t(key);
}
