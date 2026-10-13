import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService } from '../core/i18n/i18n.service';
import { keyFor } from '../core/i18n/literal-keys';
import type { ChecklistSeverity } from '../core/api.models';

/** The severities the server writes — `Severity.wireName()`, lower case. */
export type Severity = ChecklistSeverity;

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];

/**
 * A severity in words, **written once with literal keys** (decision 0019).
 *
 * The backlog, the remediation times, the scan detail, the attack paths and the EPSS queue printed
 * the wire value — "critical", "high" — in a French interface whose filters, two lines above, said
 * "Critique" and "Élevée". The checklist rules already had this map; it now serves every screen.
 */
export const SEVERITY_KEYS = {
    critical: 'severities.critical',
    high: 'severities.high',
    medium: 'severities.medium',
    low: 'severities.low',
    negligible: 'severities.negligible',
    unknown: 'severities.unknown'
} as const satisfies Record<Severity, string>;

/**
 * A severity in the reader's language; one the client does not know is shown as sent.
 *
 * Read in lower case: the API writes `critical`, but a few maps are keyed by the Java constant
 * (`mttrBySeverity['CRITICAL']`) and the attack graph's nodes carry what the scanner wrote — the
 * same word in another case is the same severity, and showing it raw would be the defect again.
 */
export function severityLabel(i18n: Pick<I18nService, 't'>, severity: string | null | undefined): string {
    if (severity == null || severity === '') return '—';
    const key = keyFor(SEVERITY_KEYS, severity.toLowerCase());
    return key ? i18n.t(key) : severity;
}

/** The tag colours a severity can take. */
export type SeverityTone = 'danger' | 'warn' | 'info' | 'secondary';

/**
 * A severity's colour, **one scale for every screen**.
 *
 * Eight screens each had their own: `high` was red on the backlog, the issue, the scan, the history
 * and the solutions, orange on the dashboard, the exceptions and the attack paths; `low` was blue,
 * grey or — on the attack paths — green, the colour of good news. A reader moving from the
 * dashboard to the backlog saw the same finding change colour.
 *
 * <p><b>Why `high` is orange and not red, though red was the more common choice.</b> The dashboard
 * is where the colours are introduced, in a legend — the backlog tiles and the time-to-resolve
 * panel paint critical red, high amber, medium blue — and that legend only reads if each level has
 * its own colour. Red for both made a critical and a high finding look alike on the backlog, where
 * telling them apart is the triage order. Four levels, four colours; `low` and below grey, never
 * green: a low finding is still a finding.
 */
export const SEVERITY_TONES = {
    critical: 'danger',
    high: 'warn',
    medium: 'info',
    low: 'secondary',
    negligible: 'secondary',
    unknown: 'secondary'
} as const satisfies Record<Severity, SeverityTone>;

/** A severity's colour, read in lower case like {@link severityLabel}; one the client does not know is grey. */
export function severityTone(severity: string | null | undefined): SeverityTone {
    const key = (severity ?? '').toLowerCase();
    return Object.hasOwn(SEVERITY_TONES, key) ? SEVERITY_TONES[key as Severity] : 'secondary';
}

@Pipe({
    name: 'severityLabel',
    // Impure like `translate`: the text changes when the language does.
    pure: false
})
export class SeverityLabelPipe implements PipeTransform {
    private readonly i18n = inject(I18nService);

    transform(severity: string | null | undefined): string {
        return severityLabel(this.i18n, severity);
    }
}
