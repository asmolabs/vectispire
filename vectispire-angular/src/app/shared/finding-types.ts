import { I18nService } from '../core/i18n/i18n.service';

/**
 * The finding types, in words, **written once with literal keys**.
 *
 * Three screens spelt this list and none agreed: the backlog offered seven types, the scan detail
 * built `issues.types.${type}` — a key the i18n check cannot see — and the issue detail translated
 * `sast` alone. Adding `plugin` and `imported` (decision 0017) to one of them would have left the
 * other two showing a raw word, which is exactly where provenance must read clearly: "analysed by
 * Vectispire" and "declared by a CI" are two types, and an auditor tells them apart by the label.
 *
 * `filterable` is the order the backlog offers them in. `ai_review` has a label and no filter entry,
 * as before: nothing here changes what the list offers beyond the two new types.
 */
export interface FindingTypeOption {
    value: string;
    label: string;
}

export function findingTypeOptions(i18n: I18nService): FindingTypeOption[] {
    return [
        { value: 'vulnerability', label: i18n.t('issues.types.vulnerability') },
        { value: 'secret', label: i18n.t('issues.types.secret') },
        { value: 'iac', label: i18n.t('issues.types.iac') },
        { value: 'license', label: i18n.t('issues.types.license') },
        { value: 'eol', label: i18n.t('issues.types.eol') },
        { value: 'sast', label: i18n.t('issues.types.sast') },
        { value: 'quality', label: i18n.t('issues.types.quality') },
        { value: 'plugin', label: i18n.t('issues.types.plugin') },
        { value: 'imported', label: i18n.t('issues.types.imported') }
    ];
}

/** Every type a row can carry, the unfiltered one included; an unknown type is shown raw. */
export function findingTypeLabel(i18n: I18nService, type: string | null | undefined): string {
    if (!type) return '—';
    if (type === 'ai_review') return i18n.t('issues.types.ai_review');
    return findingTypeOptions(i18n).find((option) => option.value === type)?.label ?? type;
}

/** The two types whose findings a tool other than Vectispire's own scanners produced. */
export function isToolProvenance(type: string | null | undefined): boolean {
    return type === 'plugin' || type === 'imported';
}
