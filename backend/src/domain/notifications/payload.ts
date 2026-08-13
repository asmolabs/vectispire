import { isAtLeast } from '../gate/policy-gate';
import { TYPE_QUALITY } from '../issues/types';

/**
 * Ce qu'un scan a changé, mis en forme pour un webhook.
 *
 * **Un webhook générique, pas une intégration Slack.** Un POST HTTP avec un corps JSON
 * documenté atteint Slack, Teams (par un flux), Discord, Mattermost, un bus interne ou un
 * script de trois lignes. Une charge propre à un fournisseur achèterait une mise en forme
 * plus jolie à un endroit au prix de tous les autres — d'où un champ `text` en tête, pour
 * que les récepteurs de discussion affichent quelque chose de lisible quand même.
 *
 * **Seulement au changement, et seulement au-dessus d'un seuil.** Une notification par
 * scan apprend aux gens à filtrer le canal.
 *
 * Ces fonctions sont pures et le message est un **instantané** : il dit ce que le scan a
 * trouvé, pas à quoi ressemblent les problèmes une fois que quelqu'un en a trié la moitié.
 */

export const SETTING_WEBHOOK_URL = 'notification_webhook_url';
export const SETTING_MIN_SEVERITY = 'notification_min_severity';
export const SETTING_NOTIFY_ON_KEV = 'notification_always_on_kev';
/** Échappatoire pour un bus interne. Désactivée par défaut : une URL de webhook qui
 *  résout vers une adresse privée est bien plus souvent une tentative de SSRF qu'un
 *  point de terminaison d'intranet. */
export const SETTING_ALLOW_PRIVATE_URL = 'notification_allow_private_url';

export const DEFAULT_MIN_SEVERITY = 'high';

/**
 * Combien de problèmes sont nommés dans la charge. Le reste est compté : un corps de
 * webhook à quatre cents entrées est un déni de service contre son lecteur, et l'API est
 * là pour la liste complète.
 */
export const MAX_DETAILED_ISSUES = 10;

/** Ce qu'un problème apporte au message. Volontairement plus étroit que l'entité. */
export interface NotifiableIssue {
    id: number;
    identifier: string | null;
    type: string;
    /** Nullable comme sur l'entité : un constat peut arriver sans sévérité, et
     *  `isAtLeast` traite l'absence comme la valeur la plus basse. */
    severity: string | null;
    isKev: boolean;
    epssScore: number | null;
    packageName: string | null;
    filePath: string | null;
    fixVersions: string | null;
    link: string | null;
}

export interface SelectionOptions {
    minSeverity: string;
    alwaysOnKev: boolean;
}

/**
 * Lesquels des problèmes nouveaux ou réapparus méritent un message.
 *
 * Une vulnérabilité activement exploitée passe **quelle que soit sa sévérité** quand
 * `alwaysOnKev` est posé — c'est tout l'intérêt du signal KEV, et la sévérité seule
 * écarterait un « moyen » exploité aujourd'hui.
 *
 * **Les constats de qualité ne qualifient jamais**, quelle que soit leur sévérité.
 * Semgrep traduit son niveau `ERROR` en `high`, qui franchit le seuil par défaut : le
 * premier scan d'un dépôt avec l'étape SAST activée déclencherait donc un webhook
 * annonçant plusieurs centaines de problèmes. Exclure le type est la correction honnête ;
 * abaisser leur sévérité pour les faire taire serait un mensonge sur la sévérité, et
 * changerait aussi leur place dans le tri du backlog.
 */
export function selectNotable(issues: NotifiableIssue[], options: SelectionOptions): NotifiableIssue[] {
    return issues.filter((issue) => {
        if (issue.type === TYPE_QUALITY) return false;
        if (options.alwaysOnKev && issue.isKev) return true;
        return isAtLeast(issue.severity, options.minSeverity);
    });
}

export interface DeltaInput {
    targetName: string;
    scanId: number;
    newIssues: NotifiableIssue[];
    reopenedIssues: NotifiableIssue[];
    resolvedCount: number;
    minSeverity: string;
}

/** Le corps du webhook. `text` en tête, pour les récepteurs qui ne lisent que ce champ. */
export function buildPayload(input: DeltaInput): Record<string, unknown> {
    const { targetName, scanId, newIssues, reopenedIssues, resolvedCount, minSeverity } = input;

    const parts: string[] = [];
    if (newIssues.length > 0) parts.push(`${newIssues.length} nouveau(x) problème(s)`);
    if (reopenedIssues.length > 0) parts.push(`${reopenedIssues.length} réapparu(s)`);

    const all = [...newIssues, ...reopenedIssues];
    const kevCount = all.filter((issue) => issue.isKev).length;
    if (kevCount > 0) parts.push(`${kevCount} activement exploité(s)`);

    let text = `Zanshin — ${targetName} : ${parts.join(', ')}`;
    if (resolvedCount > 0) text += ` (${resolvedCount} résolu(s))`;

    return {
        text,
        target: targetName,
        scan_id: scanId,
        new_count: newIssues.length,
        reopened_count: reopenedIssues.length,
        resolved_count: resolvedCount,
        kev_count: kevCount,
        min_severity: minSeverity,
        issues: all.slice(0, MAX_DETAILED_ISSUES).map(issuePayload),
        truncated: Math.max(0, all.length - MAX_DETAILED_ISSUES)
    };
}

function issuePayload(issue: NotifiableIssue): Record<string, unknown> {
    return {
        id: issue.id,
        identifier: issue.identifier,
        type: issue.type,
        severity: issue.severity,
        is_kev: issue.isKev,
        epss_score: issue.epssScore,
        package: issue.packageName,
        file_path: issue.filePath,
        // Le champ le plus utile pour qui lit l'alerte.
        fix_versions: issue.fixVersions,
        link: issue.link
    };
}
