/**
 * Ce qu'un ticket dit, et à qui il s'adresse.
 *
 * SARIF ferme la boucle vers le développeur : un constat apparaît sur la demande de fusion
 * qui l'a introduit. Ceci la ferme vers l'organisation — un problème que personne ne
 * corrigera cet après-midi doit exister là où les gens planifient leur travail, pas
 * seulement dans un tableau de bord que rien n'oblige à ouvrir.
 *
 * **Piloté par la politique de gate, pas par un second seuil.** « Ouvrir un ticket pour ce
 * qui ferait échouer une compilation » est une règle sur laquelle un opérateur sait déjà
 * raisonner, et cela laisse **un seul endroit** où « assez sérieux pour agir » est défini.
 * Inventer un `ticket_min_severity` créerait deux vocabulaires qui divergeraient, et le
 * premier rapport de bogue serait « pourquoi a-t-il ouvert un ticket là-dessus sans faire
 * échouer la compilation ».
 *
 * Fonctions pures : la mise en forme se teste sans gestionnaire de tickets.
 */

/** Ce que la mise en forme lit d'un problème. Plus étroit que l'entité, à dessein. */
export interface TicketableIssue {
    id: number;
    type: string;
    identifier: string | null;
    severity: string | null;
    packageName: string | null;
    packageVersion: string | null;
    fixVersions: string | null;
    fixState: string | null;
    isDirectDependency: boolean | null;
    filePath: string | null;
    line: number | null;
    isKev: boolean;
    epssScore: number | null;
    link: string | null;
    description: string | null;
    fingerprint: string;
}

export const PROVIDER_NONE = 'none';
export const PROVIDER_GITLAB = 'gitlab';
export const PROVIDER_JIRA = 'jira';
export const VALID_PROVIDERS = [PROVIDER_NONE, PROVIDER_GITLAB, PROVIDER_JIRA] as const;

export const DEFAULT_JIRA_ISSUE_TYPE = 'Bug';
export const DEFAULT_LABELS = 'zanshin,security';

/**
 * Plafond par balayage.
 *
 * Un premier passage sur un backlog mature ouvrirait sinon plusieurs centaines de tickets
 * d'un coup — un problème de limitation de débit, et surtout un problème social.
 */
export const MAX_TICKETS_PER_SWEEP = 20;

/** Assez court pour une liste de tickets, assez précis pour être recherchable. */
export function buildTitle(issue: TicketableIssue, targetName: string): string {
    const subject = issue.identifier || issue.type;
    const packageName = issue.packageName ? ` — ${issue.packageName}` : '';
    const severity = (issue.severity ?? 'unknown').toUpperCase();
    return `[Zanshin][${severity}] ${subject}${packageName} (${targetName})`;
}

/**
 * Le corps du ticket, écrit pour qui le prend sans contexte.
 *
 * **La version corrigée vient en tête des détails**, parce que c'est elle qui fait la
 * différence entre un ticket qu'on ferme aujourd'hui et un ticket qu'on traîne sur trois
 * itérations.
 */
export function buildBody(issue: TicketableIssue, targetName: string): string {
    const lines = [
        `Détecté par Zanshin sur **${targetName}**.`,
        '',
        `- Type : ${issue.type}`,
        `- Identifiant : ${issue.identifier || '—'}`,
        `- Sévérité : ${issue.severity ?? 'unknown'}`
    ];

    if (issue.fixVersions) lines.push(`- **Corrigé dans : ${issue.fixVersions}**`);
    else if (issue.fixState === 'not-fixed' || issue.fixState === 'wont-fix') lines.push('- Aucun correctif publié à ce jour');

    if (issue.packageName) {
        lines.push(`- Composant : ${issue.packageName}${issue.packageVersion ? ` ${issue.packageVersion}` : ''}`);
    }
    if (issue.isDirectDependency !== null) {
        lines.push(`- Dépendance : ${issue.isDirectDependency ? 'directe (déclarée par le projet)' : 'transitive'}`);
    }
    if (issue.filePath) lines.push(`- Emplacement : ${issue.filePath}${issue.line ? `:${issue.line}` : ''}`);
    if (issue.isKev) lines.push('- ⚠️ Exploitation active connue (catalogue CISA KEV)');
    if (issue.epssScore !== null) lines.push(`- Probabilité d'exploitation (EPSS) : ${(issue.epssScore * 100).toFixed(1)} %`);
    if (issue.link) lines.push(`- Référence : ${issue.link}`);

    // Tronquée : une description de CVE peut faire plusieurs kilooctets, et un ticket
    // qu'on doit dérouler pour trouver la conclusion n'est pas lu.
    if (issue.description) lines.push('', issue.description.slice(0, 1000));

    lines.push(
        '',
        `Problème Zanshin #${issue.id} — empreinte \`${issue.fingerprint}\`.`,
        'Ce ticket a été ouvert parce que ce problème ferait échouer une compilation selon la politique de gate en ' +
            'vigueur pour cette cible.'
    );
    return lines.join('\n');
}

/** Les étiquettes, lues du réglage. Une liste vide est un état valide. */
export function parseLabels(raw: string): string[] {
    return raw
        .split(',')
        .map((label) => label.trim())
        .filter((label) => label !== '');
}

/** Le fournisseur, normalisé. Tout ce qui sort du vocabulaire vaut « aucun ». */
export function parseProvider(raw: string): string {
    const value = (raw ?? '').trim().toLowerCase();
    return (VALID_PROVIDERS as readonly string[]).includes(value) ? value : PROVIDER_NONE;
}
