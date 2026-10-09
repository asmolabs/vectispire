import { AiDeterministic } from '../core/api.models';
import { I18nService } from '../core/i18n/i18n.service';

/**
 * The advisor's own wording, rebuilt in the reader's language, **written once for both screens**.
 *
 * The issues list and the EPSS page each carried the sentences in their templates, and each had a
 * `kevChance` that printed an EPSS probability of 85 % whenever a listed CVE had none — the same
 * figure the server's fallback made up, invented a second time on the screen. What the product
 * holds about a vulnerability is its component, the fix recorded, the KEV listing and the EPSS
 * score; a null among them is unknown, and these sentences say so rather than filling it in.
 */
export function adviceSummary(i18n: I18nService, identifier: string, own: AiDeterministic): string {
    if (!own.packageName) {
        return i18n.t('ai.summary_no_component', { id: identifier });
    }
    return i18n.t('ai.summary', {
        id: identifier,
        package: own.packageName,
        version: own.currentVersion ?? i18n.t('ai.unknown')
    });
}

/** The KEV listing and the EPSS score, each as the stored feeds hold it — unknown included. */
export function adviceExploitation(i18n: I18nService, own: AiDeterministic): string {
    const kev =
        own.kev === 'LISTED'
            ? i18n.t('ai.kev_listed')
            : own.kev === 'NOT_LISTED'
              ? i18n.t('ai.kev_not_listed')
              : i18n.t('ai.kev_unknown');
    const epss =
        own.exploitProbability == null
            ? i18n.t('ai.epss_unknown')
            : i18n.t('ai.epss', { chance: epssPercent(i18n, own.exploitProbability) });
    return `${kev} ${epss}`;
}

/** What to upgrade to, only when a fixed version is recorded. */
export function adviceFix(i18n: I18nService, own: AiDeterministic): string {
    if (!own.targetVersion) {
        return i18n.t('ai.fix_none');
    }
    if (!own.packageName) {
        return i18n.t('ai.fix_action_no_component', { target: own.targetVersion });
    }
    return i18n.t('ai.fix_action', {
        package: own.packageName,
        version: own.currentVersion ?? i18n.t('ai.unknown'),
        target: own.targetVersion
    });
}

/**
 * A probability as a percentage, to three decimals at most. One decimal wrote 0.0 % for most of
 * FIRST's scores — measured, small, and not zero. In the reader's decimal mark: French reads
 * "0,043 %", and `toFixed` wrote the English point on both screens.
 */
export function epssPercent(i18n: Pick<I18nService, 'decimal'>, probability: number): string {
    return i18n.decimal(probability * 100, 3);
}
