import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService } from '../core/i18n/i18n.service';
import { keyFor } from '../core/i18n/literal-keys';

/**
 * A target's kind in words — the verdict register's own pair, so "Image" reads the same on every
 * screen. The EPSS queue printed `REPOSITORY`, the blast radius tagged `CONTAINER`, the ranking wrote
 * the wire value and the recent scans an English "repository" in the French interface.
 */
export const TARGET_KIND_KEYS = {
    repository: 'gate_verdicts.kind.repository',
    container: 'gate_verdicts.kind.container'
} as const;

/** Read in lower case: the blast radius and the EPSS queue send the Java constant, the rest the wire name. */
export function targetKindLabel(i18n: Pick<I18nService, 't'>, kind: string | null | undefined): string {
    if (kind == null || kind === '') return '—';
    const key = keyFor(TARGET_KIND_KEYS, kind.toLowerCase());
    return key ? i18n.t(key) : kind;
}

@Pipe({
    name: 'targetKind',
    // Impure like `translate`: the text changes when the language does.
    pure: false
})
export class TargetKindPipe implements PipeTransform {
    private readonly i18n = inject(I18nService);

    transform(kind: string | null | undefined): string {
        return targetKindLabel(this.i18n, kind);
    }
}
