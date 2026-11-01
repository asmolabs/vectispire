import { Pipe, PipeTransform } from '@angular/core';
import type { LicenseRiskCategory } from '../../core/api.models';

/** The tag colours a licence's risk or compatibility can take. */
export type LicenseTone = 'success' | 'warn' | 'danger' | 'secondary';

/** A risk category's colour: permissive is good news, any copyleft a warning or worse, the unknown grey. */
export function riskTone(category: string): LicenseTone {
    switch (category) {
        case 'PERMISSIVE':
            return 'success';
        case 'WEAK_COPYLEFT':
            return 'warn';
        case 'STRONG_COPYLEFT':
            return 'danger';
        case 'FORBIDDEN':
            return 'danger';
        default:
            return 'secondary';
    }
}

/** A compatibility verdict's colour; a verdict this client does not know is grey. */
export function compatTone(compatibility: string): LicenseTone {
    switch (compatibility) {
        case 'COMPATIBLE':
            return 'success';
        case 'CONDITIONAL':
            return 'warn';
        case 'INCOMPATIBLE_BLOCKING':
            return 'danger';
        default:
            return 'secondary';
    }
}

/**
 * `item.riskCategory | riskTone`. Pure: the colour depends on the value alone, so Angular calls it
 * again only for a new one — the three tables called a method per row on every pass.
 */
@Pipe({ name: 'riskTone' })
export class RiskTonePipe implements PipeTransform {
    transform(category: string): LicenseTone {
        return riskTone(category);
    }
}

/** `conflict.compatibility | compatTone`, pure for the same reason. */
@Pipe({ name: 'compatTone' })
export class CompatTonePipe implements PipeTransform {
    transform(compatibility: string): LicenseTone {
        return compatTone(compatibility);
    }
}

/**
 * `category | disallowedIn: draftDisallowed` — whether the policy draft refuses a category. The draft
 * is a plain field the toggles replace (never mutate), so a pure pipe given it follows every toggle
 * where a computed would have frozen on the first.
 */
@Pipe({ name: 'disallowedIn' })
export class DisallowedInPipe implements PipeTransform {
    transform(category: LicenseRiskCategory, disallowed: readonly LicenseRiskCategory[]): boolean {
        return disallowed.includes(category);
    }
}
