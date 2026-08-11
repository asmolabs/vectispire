import { EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { buildFingerprint } from '../domain/issues/issue-fingerprint';
import { Finding, Issue, STATE_OPEN, STATE_RESOLVED, Scan, TRIAGE_FIXED, TRIAGE_UNDER_REVIEW } from '../persistence/entities';
import { IssueRepository } from '../repositories/issue.repository';

/**
 * Les champs qu'un nouveau constat rafraîchit sur un problème existant.
 *
 * `packageVersion` en fait partie alors qu'il est **exclu de l'empreinte** : c'est
 * exactement l'intention. Une dépendance obsolète qui le reste à travers trois montées
 * de version est *un* problème dont la version affichée suit, pas trois problèmes
 * distincts dont le triage s'évapore à chaque correctif.
 */
const REFRESHED_FROM_FINDING = [
    'packageVersion',
    'line',
    // Rafraîchi comme le reste, et sauté quand il est nul : un scan de conteneur ne
    // distingue pas direct de transitif, et ne doit pas effacer ce qu'un scan de dépôt
    // avait établi.
    'isDirectDependency',
    'severity',
    'source',
    'epssScore',
    'isKev',
    'cvssScore',
    'cvssVector',
    'fixState',
    'fixVersions',
    'link'
] as const;

type RefreshedField = (typeof REFRESHED_FROM_FINDING)[number];

export interface SyncResult {
    new: number;
    resolved: number;
    reopened: number;
    stillOpen: number;
    /**
     * Les problèmes eux-mêmes, pas seulement les compteurs : une notification doit dire
     * *ce qui* est apparu, et reconstruire cette liste après coup demanderait de
     * re-déduire « lesquels sont nouveaux » — la seule chose que cette méthode sait
     * déjà avec certitude.
     */
    newIssues: Issue[];
    reopenedIssues: Issue[];
}

export interface SyncOptions {
    /**
     * Les types de constats **réellement observés** par ce scan. Fourni par l'appelant,
     * jamais déduit des constats présents.
     *
     * C'est le pivot de toute la résolution, et la subtilité la plus coûteuse à rater
     * du portage : « le scanner de secrets a tourné et n'a rien trouvé » doit résoudre
     * les problèmes de type secret, tandis que « aucun constat de secret parce qu'on
     * n'a pas cherché » doit les laisser intacts. Déduire l'ensemble des constats
     * présents ne peut pas distinguer les deux, et se tromper résout en silence tout
     * l'historique d'un type — sans erreur, sans journal.
     */
    scannedTypes: Iterable<string>;
    /** Descriptions par identifiant, quand le scanner en fournit. */
    descriptions?: Record<string, string>;
    /**
     * Appelé avec le résultat **pendant que la transaction est encore ouverte**.
     *
     * Existe pour un seul appelant et une seule raison : l'outbox de notification doit
     * voir sa ligne devenir durable au même instant que les problèmes qu'elle décrit.
     * L'enfiler après le retour laisserait la fenêtre où une panne perd la
     * notification — le défaut même que l'outbox supprime.
     */
    beforeCommit?: (result: SyncResult) => Promise<void> | void;
}

/**
 * Le repli des constats d'un scan dans l'historique des problèmes.
 *
 * **N'est appelé que pour un scan terminé.** Un scan échoué ou interrompu n'a rien
 * observé, et traiter cela comme une preuve d'absence marquerait résolu tout le backlog
 * d'une cible.
 *
 * Le service ne porte pas de session : `sync` reçoit l'`EntityManager` de la
 * transaction que l'appelant possède. C'est la contrainte qui rend possible la
 * garantie du hook `beforeCommit`.
 */
export class IssueSyncService {
    constructor(private readonly issues: IssueRepository = new IssueRepository()) {}

    async sync(manager: EntityManager, scan: Scan, findings: Finding[], options: SyncOptions): Promise<SyncResult> {
        const scannedTypes = [...new Set(options.scannedTypes)];
        const descriptions = options.descriptions ?? {};
        const moment = now();

        // Un même constat peut se répéter dans un scan — le même CVE à deux endroits du
        // même paquet. Le problème est un, ses occurrences sont multiples.
        const byFingerprint = new Map<string, Finding[]>();
        for (const finding of findings) {
            const fingerprint = buildFingerprint({
                repoId: scan.repoId,
                containerId: scan.containerId,
                findingType: finding.type,
                identifier: finding.identifier,
                purl: finding.purl,
                packageName: finding.packageName,
                filePath: finding.filePath
            });
            const occurrences = byFingerprint.get(fingerprint);
            if (occurrences) occurrences.push(finding);
            else byFingerprint.set(fingerprint, [finding]);
        }

        const existing = await this.issues.findByFingerprints(manager, [...byFingerprint.keys()]);
        const newIssues: Issue[] = [];
        const reopenedIssues: Issue[] = [];
        const touched: Issue[] = [];

        for (const [fingerprint, occurrences] of byFingerprint) {
            const finding = occurrences[0];
            let issue = existing.get(fingerprint);

            if (!issue) {
                issue = this.createIssue(scan, fingerprint, finding, moment);
                issue.description = descriptions[finding.identifier ?? ''] ?? null;
                newIssues.push(issue);
            } else {
                if (issue.state === STATE_RESOLVED) {
                    this.reopen(issue);
                    reopenedIssues.push(issue);
                }
                this.refresh(issue, finding, scan, moment);
                if (!issue.description) issue.description = descriptions[finding.identifier ?? ''] ?? null;
            }
            touched.push(issue);
        }

        // Enregistré avant de rattacher les occurrences : un problème neuf n'a pas
        // encore d'identifiant, et un constat ne peut pas pointer vers rien.
        const saved = await this.issues.save(manager, touched);
        const idByFingerprint = new Map(saved.map((issue) => [issue.fingerprint, issue.id]));
        for (const [fingerprint, occurrences] of byFingerprint) {
            const issueId = idByFingerprint.get(fingerprint);
            for (const occurrence of occurrences) occurrence.issueId = issueId ?? null;
        }

        const resolved = await this.resolveDisappeared(manager, scan, scannedTypes, new Set(byFingerprint.keys()), moment);

        scan.newIssuesCount = newIssues.length;
        scan.resolvedIssuesCount = resolved;

        const result: SyncResult = {
            new: newIssues.length,
            resolved,
            reopened: reopenedIssues.length,
            stillOpen: byFingerprint.size - newIssues.length - reopenedIssues.length,
            newIssues,
            reopenedIssues
        };

        if (options.beforeCommit) {
            try {
                await options.beforeCommit(result);
            } catch {
                // Un hook qui échoue ne doit pas faire perdre les résultats du scan, qui
                // sont ce qui a de la valeur dans cette transaction. L'appelant commite
                // quand même, sans ce que le hook voulait ajouter.
            }
        }

        return result;
    }

    private createIssue(scan: Scan, fingerprint: string, finding: Finding, moment: Date): Issue {
        const issue = new Issue();
        issue.repoId = scan.repoId;
        issue.containerId = scan.containerId;
        issue.fingerprint = fingerprint;
        issue.type = finding.type;
        issue.identifier = finding.identifier;
        issue.purl = finding.purl;
        issue.packageName = finding.packageName;
        issue.filePath = finding.filePath;
        issue.state = STATE_OPEN;
        issue.firstSeenAt = moment;
        issue.lastSeenAt = moment;
        issue.resolvedAt = null;
        issue.firstSeenScanId = scan.id;
        issue.lastSeenScanId = scan.id;
        issue.timesSeen = 1;
        issue.triageStatus = TRIAGE_UNDER_REVIEW;
        issue.triageJustification = null;
        issue.triageComment = null;
        issue.triagedBy = null;
        issue.triagedAt = null;
        issue.triageExpiresAt = null;
        issue.ticketRef = null;
        issue.ticketUrl = null;
        issue.description = null;

        for (const field of REFRESHED_FROM_FINDING) {
            assignRefreshed(issue, field, (finding as unknown as Record<string, unknown>)[field] ?? null);
        }
        // `bool(finding.is_kev)` : la colonne n'est pas nullable côté problème, alors
        // qu'un constat peut arriver avec la valeur absente.
        issue.isKev = Boolean(finding.isKev);
        return issue;
    }

    private refresh(issue: Issue, finding: Finding, scan: Scan, moment: Date): void {
        for (const field of REFRESHED_FROM_FINDING) {
            const value = (finding as unknown as Record<string, unknown>)[field];
            // L'enrichissement EPSS/KEV tourne *après* cette réconciliation pour un
            // constat tout neuf : un score nul sur cette passe ne doit pas effacer ce
            // qu'un scan précédent avait déjà établi.
            if (value !== null && value !== undefined) assignRefreshed(issue, field, value);
        }
        issue.lastSeenAt = moment;
        issue.lastSeenScanId = scan.id;
        issue.timesSeen = (issue.timesSeen || 0) + 1;
        issue.state = STATE_OPEN;
        issue.resolvedAt = null;
    }

    /**
     * Un problème résolu qu'on revoit.
     *
     * Seul un triage `fixed` est effacé : il vient d'être factuellement contredit, et le
     * laisser cacherait une régression derrière une décision périmée. Un jugement
     * `not_affected` porte sur l'exposition du code, pas sur la présence du paquet — il
     * survit donc, et reste visible dans l'historique de triage pour révision.
     */
    private reopen(issue: Issue): void {
        if (issue.triageStatus === TRIAGE_FIXED) {
            issue.triageStatus = TRIAGE_UNDER_REVIEW;
            issue.triageJustification = null;
            issue.triagedAt = null;
            issue.triagedBy = null;
        }
    }

    private async resolveDisappeared(manager: EntityManager, scan: Scan, scannedTypes: string[], seen: Set<string>, moment: Date): Promise<number> {
        // Aucun type observé : rien ne peut être déclaré disparu. C'est le garde-fou
        // qui rend inoffensif un appel mal formé.
        if (scannedTypes.length === 0) return 0;

        const candidates = await this.issues.findOpenByTarget(manager, { repoId: scan.repoId, containerId: scan.containerId }, scannedTypes);

        const disappeared = candidates.filter((issue) => !seen.has(issue.fingerprint));
        for (const issue of disappeared) {
            issue.state = STATE_RESOLVED;
            issue.resolvedAt = moment;
        }
        await this.issues.save(manager, disappeared);
        return disappeared.length;
    }
}

/** `assign` typé, pour ne pas perdre la vérification sur la liste des champs. */
function assignRefreshed(issue: Issue, field: RefreshedField, value: unknown): void {
    (issue as unknown as Record<string, unknown>)[field] = value;
}
