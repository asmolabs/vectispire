import { QUALITY_TYPES } from '../gate/policy-gate';

/**
 * Formats d'export des problèmes : SARIF, OpenVEX et CSV.
 *
 * VEX est la raison pour laquelle les décisions de triage sont stockées dans le
 * vocabulaire de la norme plutôt qu'en texte libre — c'est donc une sérialisation, pas
 * une traduction. Chaque champ dont une déclaration OpenVEX a besoin est déjà sur le
 * problème ; rien ici n'a à déduire ou à inventer, et c'est ce qui rend le document
 * assez fiable pour être remis à un client ou à un auditeur.
 *
 * SARIF a un autre but : OpenVEX et CSV s'adressent à des gens hors du pipeline,
 * SARIF existe pour qu'un constat cesse de vivre uniquement dans Zanshin. C'est ce
 * qu'ingèrent nativement GitHub code scanning, GitLab et Azure DevOps, et donc ce qui
 * met un problème devant la personne qui l'a introduit, annoté sur la ligne, dans la
 * demande de fusion — au lieu d'un tableau de bord qu'elle n'a aucune raison d'ouvrir.
 *
 * Fonctions pures : la couche HTTP décide comment les livrer, et un bouton de
 * téléchargement dans l'interface les réutilise sans modification.
 *
 * Vérifié contre `test/vectors/exports.json`, produit par le vrai module Python.
 */

export const OPENVEX_CONTEXT = 'https://openvex.dev/ns/v0.2.0';
export const SARIF_VERSION = '2.1.0';
export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

const STATE_RESOLVED = 'resolved';
const TRIAGE_UNDER_REVIEW = 'under_review';
const TRIAGE_AFFECTED = 'affected';
const TRIAGE_NOT_AFFECTED = 'not_affected';
const TRIAGE_FIXED = 'fixed';

/**
 * Le vocabulaire de triage de Zanshin est déjà celui d'OpenVEX, à une exception près :
 * `under_review` s'écrit `under_investigation` dans la spécification.
 */
const VEX_STATUS: Record<string, string> = {
    [TRIAGE_UNDER_REVIEW]: 'under_investigation',
    [TRIAGE_AFFECTED]: 'affected',
    [TRIAGE_NOT_AFFECTED]: 'not_affected',
    [TRIAGE_FIXED]: 'fixed'
};

/**
 * SARIF a quatre niveaux et aucune notion de « critique ». Tout ce qu'un outil de
 * sécurité appellerait critique ou élevé doit atterrir sur `error`, parce que
 * `warning` est ce qu'un relecteur fait défiler sans lire.
 */
const SARIF_LEVEL: Record<string, string> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
    negligible: 'note',
    unknown: 'warning'
};

/**
 * GitHub classe et filtre sur cette propriété, **pas** sur `level` : c'est elle qui
 * garde une critique distinguable d'une élevée une fois que les deux sont `error`.
 * Les valeurs suivent les tranches CVSS que GitHub documente.
 */
const SECURITY_SEVERITY: Record<string, string> = {
    critical: '9.5',
    high: '8.0',
    medium: '5.5',
    low: '3.0',
    negligible: '1.0'
};

const ISSUE_TYPE_LABEL: Record<string, string> = {
    vulnerability: 'Vulnérabilité',
    secret: 'Secret exposé',
    iac: "Configuration d'infrastructure",
    license: 'Licence',
    eol: 'Fin de vie',
    ai_review: 'Revue IA',
    sast: 'Code vulnérable',
    quality: 'Qualité du code'
};

export const CSV_COLUMNS = [
    'id',
    'type',
    'identifier',
    'severity',
    'cvss_score',
    'epss_score',
    'is_kev',
    'package_name',
    'package_version',
    'purl',
    'dependency',
    'file_path',
    'line',
    'fix_state',
    'fix_versions',
    'state',
    'triage_status',
    'triage_justification',
    'triaged_by',
    'triaged_at',
    'triage_expires_at',
    'first_seen_at',
    'last_seen_at',
    'times_seen',
    'link'
] as const;

/**
 * Un problème tel que les exports le lisent.
 *
 * Les horodatages sont des **chaînes** au format `datetime.isoformat()` — jamais des
 * `Date`, qui perdent la microseconde et appliquent un fuseau (voir
 * `common/timestamp.ts` et `persistence/pg-types.ts`).
 */
export interface ExportableIssue {
    id: number;
    fingerprint: string | null;
    type: string | null;
    identifier: string | null;
    severity: string | null;
    cvssScore: number | null;
    epssScore: number | null;
    isKev: boolean | null;
    packageName: string | null;
    packageVersion: string | null;
    purl: string | null;
    isDirectDependency: boolean | null;
    filePath: string | null;
    line: number | null;
    fixState: string | null;
    fixVersions: string | null;
    link: string | null;
    description: string | null;
    state: string | null;
    triageStatus: string | null;
    triageJustification: string | null;
    triageComment: string | null;
    triagedBy: string | null;
    triagedAt: string | null;
    triageExpiresAt: string | null;
    firstSeenAt: string | null;
    lastSeenAt: string | null;
    timesSeen: number | null;
}

// --------------------------------------------------------------------------- OpenVEX

export interface OpenVexOptions {
    author: string;
    productId: string;
    documentId: string;
    /** Fourni par l'appelant : un document VEX est une assertion sur qui a dit quoi
     *  et quand, ce qui appartient à celui qui le publie, pas à une fonction utilitaire. */
    timestamp: string;
    version?: number;
}

/**
 * Un document OpenVEX pour un produit, à partir de ses problèmes de vulnérabilité.
 *
 * Seuls les problèmes de type `vulnerability` sont inclus : VEX est défini sur des
 * identifiants de vulnérabilité, et un secret codé en dur ou un contrôle IaC en échec
 * n'a pas de CVE à propos de quoi se prononcer. Les problèmes sans identifiant sont
 * écartés pour la même raison — une déclaration anonyme n'en est pas une.
 */
export function buildOpenVexDocument(issues: Iterable<ExportableIssue>, options: OpenVexOptions): Record<string, unknown> {
    const statements: Record<string, unknown>[] = [];

    for (const issue of issues) {
        if (issue.type !== 'vulnerability' || !issue.identifier) continue;

        let status = VEX_STATUS[issue.triageStatus ?? ''] ?? 'under_investigation';
        // Un problème résolu et jamais trié est factuellement corrigé : le scanner a
        // cessé de le voir. Dire « sous investigation » de quelque chose qui a disparu
        // serait trompeur dans un document fait pour répondre exactement à ça.
        if (issue.state === STATE_RESOLVED && issue.triageStatus === TRIAGE_UNDER_REVIEW) {
            status = 'fixed';
        }

        const statement: Record<string, unknown> = {
            vulnerability: { name: issue.identifier },
            products: [{ '@id': options.productId }],
            status
        };

        if (status === 'not_affected') {
            // Exigée par la spécification pour ce statut, et garantie présente par
            // `IssueService.triage`.
            statement.justification = issue.triageJustification;
            if (issue.triageComment) statement.impact_statement = issue.triageComment;
        } else if (status === 'affected' && issue.triageComment) {
            // Pour « affected », le texte libre appartient à l'énoncé d'action.
            statement.action_statement = issue.triageComment;
        }

        if (issue.purl) {
            statement.products = [{ '@id': options.productId, identifiers: { purl: issue.purl } }];
        }
        if (issue.triagedAt) statement.timestamp = issue.triagedAt;
        else if (issue.lastSeenAt) statement.timestamp = issue.lastSeenAt;

        statements.push(statement);
    }

    return {
        '@context': OPENVEX_CONTEXT,
        '@id': options.documentId,
        author: options.author,
        timestamp: options.timestamp,
        version: options.version ?? 1,
        tooling: 'Zanshin',
        statements
    };
}

// ----------------------------------------------------------------------------- SARIF

export interface SarifOptions {
    targetName: string;
    toolVersion?: string;
    informationUri?: string | null;
}

/**
 * Un journal SARIF 2.1.0 pour les problèmes d'une cible.
 *
 * Décisions qui méritent d'être énoncées, parce que SARIF est assez permissif pour
 * qu'un document techniquement valide reste inutile dans une interface de code
 * scanning :
 *
 * - **Les problèmes triés sont des `suppressions`, pas des omissions.** Les retirer
 *   ferait qu'une plateforme les re-signale comme neufs au téléversement suivant,
 *   défaisant le travail de triage ; et une suppression porte sa justification, donc
 *   le relecteur voit *pourquoi* c'est écarté. `not_affected` et `fixed` sont
 *   supprimés, `affected` ne l'est pas — décider qu'un problème est réel doit rester
 *   visible.
 * - **Les problèmes résolus sont exclus.** Ils ont disparu ; le rôle de SARIF est
 *   l'état actuel de la branche qu'on compile.
 * - **`partialFingerprints` porte l'empreinte de Zanshin**, ce qui permet à la
 *   plateforme d'apparier un problème d'un téléversement à l'autre même si le fichier
 *   bouge ou si la ligne se décale.
 * - **Chaque résultat a une location**, avec repli sur la racine du dépôt quand un
 *   problème de dépendance n'a pas de fichier. GitHub jette silencieusement les
 *   résultats sans location, donc une location « honnêtement vide » ferait
 *   disparaître les constats de vulnérabilité — c'est-à-dire l'essentiel d'entre eux.
 *
 * Les règles sont émises par identifiant distinct plutôt que par problème : c'est ce
 * que le modèle SARIF entend par règle, et ce qui permet à une plateforme de grouper.
 */
export function buildSarifDocument(issues: Iterable<ExportableIssue>, options: SarifOptions): Record<string, unknown> {
    const current = [...issues].filter((issue) => issue.state !== STATE_RESOLVED);

    // `Map` et non un objet : l'ordre d'insertion des règles détermine `ruleIndex`,
    // et un objet réordonnerait les clés qui ressemblent à des entiers.
    const rules = new Map<string, Record<string, unknown>>();
    const ruleIndex = new Map<string, number>();
    const results: Record<string, unknown>[] = [];

    for (const issue of current) {
        const ruleId = sarifRuleId(issue);
        if (!rules.has(ruleId)) {
            ruleIndex.set(ruleId, rules.size);
            rules.set(ruleId, sarifRule(issue, ruleId));
        }

        const properties: Record<string, unknown> = {
            zanshinIssueId: issue.id,
            type: issue.type,
            firstSeen: issue.firstSeenAt ?? '',
            timesSeen: issue.timesSeen || 1
        };
        if (issue.isDirectDependency !== null && issue.isDirectDependency !== undefined) {
            properties.dependency = issue.isDirectDependency ? 'direct' : 'transitive';
        }

        const result: Record<string, unknown> = {
            ruleId,
            ruleIndex: ruleIndex.get(ruleId),
            level: SARIF_LEVEL[(issue.severity || 'unknown').toLowerCase()] ?? 'warning',
            message: { text: sarifMessage(issue) },
            locations: [sarifLocation(issue)],
            partialFingerprints: { zanshinIssueFingerprint: issue.fingerprint },
            properties
        };

        if (isSuppressed(issue)) {
            result.suppressions = [
                {
                    // « external » : la décision a été prise dans Zanshin, pas dans une
                    // annotation du source, ce que documente ce genre de suppression.
                    kind: 'external',
                    justification: suppressionJustification(issue)
                }
            ];
        }
        results.push(result);
    }

    const driver: Record<string, unknown> = {
        name: 'Zanshin',
        version: options.toolVersion ?? '1.0.0'
    };
    // Absente et non nulle quand elle n'est pas fournie : `**({...} if x else {})`.
    if (options.informationUri) driver.informationUri = options.informationUri;
    driver.rules = [...rules.values()];

    return {
        $schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: [
            {
                tool: { driver },
                results,
                properties: { target: options.targetName }
            }
        ]
    };
}

/** `security` seulement pour ce qui est réellement un constat de sécurité. */
function sarifTags(issue: ExportableIssue): string[] {
    if (issue.type != null && QUALITY_TYPES.includes(issue.type)) return ['quality', issue.type];
    return ['security', issue.type as string];
}

/**
 * Stable, et cloisonné par type.
 *
 * Une règle gitleaks et un contrôle checkov peuvent entrer en collision sur un
 * identifiant, et une plateforme indexée sur `ruleId` fondrait alors deux classes de
 * problèmes sans rapport sous un même titre.
 */
function sarifRuleId(issue: ExportableIssue): string {
    return `zanshin/${issue.type}/${issue.identifier || 'unspecified'}`;
}

function sarifRule(issue: ExportableIssue, ruleId: string): Record<string, unknown> {
    const label = (issue.type != null ? ISSUE_TYPE_LABEL[issue.type] : undefined) ?? issue.type;
    const properties: Record<string, unknown> = { tags: sarifTags(issue) };

    const rule: Record<string, unknown> = {
        id: ruleId,
        name: (issue.identifier || issue.type || '').replace(/ /g, ''),
        shortDescription: { text: `${label} : ${issue.identifier || 'non identifié'}` },
        properties
    };

    if (issue.description) rule.fullDescription = { text: issue.description.slice(0, 1000) };
    if (issue.link) rule.helpUri = issue.link;

    const severity = (issue.severity || '').toLowerCase();
    if (severity in SECURITY_SEVERITY) properties['security-severity'] = SECURITY_SEVERITY[severity];

    return rule;
}

/**
 * Ce que le développeur lit dans la demande de fusion, donc ce qui dit quoi faire.
 *
 * La version corrigée est la chose la plus utile à mettre devant quelqu'un qui a
 * trente secondes : elle transforme « il y a une CVE » en « change cette ligne ».
 */
function sarifMessage(issue: ExportableIssue): string {
    const parts: string[] = [];
    if (issue.packageName) {
        parts.push(issue.packageVersion ? `${issue.packageName} ${issue.packageVersion}` : issue.packageName);
    }
    parts.push(issue.identifier || (issue.type != null ? ISSUE_TYPE_LABEL[issue.type] : undefined) || (issue.type as string));

    let message = parts.join(' — ');
    if (issue.fixVersions) message += ` — corrigé dans ${issue.fixVersions}`;
    else if (issue.fixState === 'not-fixed') message += ' — aucun correctif publié';
    if (issue.isKev) message += ' — exploitation active connue (CISA KEV)';
    if (issue.isDirectDependency === false) message += ' — dépendance transitive';
    return message;
}

function sarifLocation(issue: ExportableIssue): Record<string, unknown> {
    const physicalLocation: Record<string, unknown> = {
        // Une URI relative, comme SARIF l'exige pour du source que le consommateur
        // résout contre le dépôt qu'il vient d'extraire.
        artifactLocation: { uri: issue.filePath || '.' }
    };
    if (issue.line) physicalLocation.region = { startLine: Math.trunc(issue.line) };

    const location: Record<string, unknown> = { physicalLocation };
    if (issue.purl) location.logicalLocations = [{ name: issue.purl, kind: 'package' }];
    return location;
}

function isSuppressed(issue: ExportableIssue): boolean {
    return issue.triageStatus === TRIAGE_NOT_AFFECTED || issue.triageStatus === TRIAGE_FIXED;
}

function suppressionJustification(issue: ExportableIssue): string {
    const parts: string[] = [issue.triageStatus as string];
    if (issue.triageJustification) parts.push(issue.triageJustification);
    if (issue.triageComment) parts.push(issue.triageComment);
    if (issue.triagedBy) parts.push(`décidé par ${issue.triagedBy}`);
    // `.date().isoformat()` en Python : la partie date seule, donc les dix premiers
    // caractères d'un isoformat.
    if (issue.triageExpiresAt) parts.push(`à revoir le ${issue.triageExpiresAt.slice(0, 10)}`);
    return parts.join(' — ');
}

// ------------------------------------------------------------------------------- CSV

/**
 * CSV plat des problèmes, une ligne chacun, pour le reporting et les tableurs.
 *
 * Délibérément une colonne par champ stocké plutôt qu'un sous-ensemble choisi : les
 * gens qui demandent du CSV sont ceux qui veulent croiser eux-mêmes.
 */
export function buildIssuesCsv(issues: Iterable<ExportableIssue>): string {
    const rows: string[] = [CSV_COLUMNS.join(',')];

    for (const issue of issues) {
        rows.push(
            [
                String(issue.id),
                issue.type ?? '',
                issue.identifier || '',
                issue.severity || '',
                pythonNumber(issue.cvssScore),
                pythonNumber(issue.epssScore),
                issue.isKev ? 'true' : 'false',
                issue.packageName || '',
                issue.packageVersion || '',
                issue.purl || '',
                dependencyLabel(issue.isDirectDependency),
                issue.filePath || '',
                issue.line ? String(issue.line) : '',
                issue.fixState || '',
                issue.fixVersions || '',
                issue.state ?? '',
                issue.triageStatus ?? '',
                issue.triageJustification || '',
                issue.triagedBy || '',
                issue.triagedAt || '',
                issue.triageExpiresAt || '',
                issue.firstSeenAt || '',
                issue.lastSeenAt || '',
                String(issue.timesSeen || 1),
                issue.link || ''
            ]
                .map(quoteCsvField)
                .join(',')
        );
    }

    // `csv.writer` de Python termine ses lignes en CRLF (dialecte « excel »), y
    // compris la dernière. Utiliser `\n` produirait un fichier que la plupart des
    // outils liraient quand même — donc un écart que personne ne remarquerait avant
    // qu'un consommateur strict ne le refuse.
    return rows.map((row) => `${row}\r\n`).join('');
}

/**
 * Guillemets à la manière de `QUOTE_MINIMAL` : on ne cite que si le champ contient le
 * séparateur, un guillemet, ou un caractère de fin de ligne. Les guillemets du
 * contenu sont doublés.
 */
function quoteCsvField(value: string): string {
    if (!/[",\r\n]/.test(value)) return value;
    return `"${value.replace(/"/g, '""')}"`;
}

/**
 * Vide plutôt qu'« unknown » : une colonne remplie du mot « unknown » se lit comme un
 * constat sur la dépendance, alors que l'énoncé honnête est qu'on n'a rien à en dire.
 */
function dependencyLabel(isDirect: boolean | null | undefined): string {
    if (isDirect === null || isDirect === undefined) return '';
    return isDirect ? 'direct' : 'transitive';
}

/**
 * `str(float)` de Python, qui garde la décimale des valeurs entières : `str(9.0)`
 * rend « 9.0 », là où `String(9)` rend « 9 » en JavaScript.
 *
 * Sur une colonne de score CVSS, la moitié des valeurs sont entières — l'écart
 * toucherait donc une ligne sur deux d'un export remis à un auditeur.
 */
function pythonNumber(value: number | null | undefined): string {
    if (value === null || value === undefined) return '';
    return Number.isInteger(value) ? `${value}.0` : String(value);
}
