import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService } from '../core/i18n/i18n.service';
import { keyFor } from '../core/i18n/literal-keys';

/**
 * Which gate policy decided, in words. The verdict register printed the stored value — "built-in" on
 * the French screenshots, `BUILT_IN` from a real server — and the security page "global v2".
 *
 * Read in lower case, and under both spellings: the register stores `PolicyResolution.Source`'s name
 * (`TARGET`, `GLOBAL`, `BUILT_IN`), the security overview sends `target`, `global`, `built-in`.
 */
export const POLICY_SOURCE_KEYS = {
    target: 'gate_verdicts.policy_source.target',
    global: 'gate_verdicts.policy_source.global',
    built_in: 'gate_verdicts.policy_source.built_in',
    'built-in': 'gate_verdicts.policy_source.built_in'
} as const;

/** A source this client does not know is shown as sent, never as a key path. */
export function policySourceLabel(i18n: Pick<I18nService, 't'>, source: string | null | undefined): string {
    if (source == null || source === '') return '—';
    const key = keyFor(POLICY_SOURCE_KEYS, source.toLowerCase());
    return key ? i18n.t(key) : source;
}

@Pipe({
    name: 'policySource',
    // Impure like `translate`: the text changes when the language does.
    pure: false
})
export class PolicySourcePipe implements PipeTransform {
    private readonly i18n = inject(I18nService);

    transform(source: string | null | undefined): string {
        return policySourceLabel(this.i18n, source);
    }
}
