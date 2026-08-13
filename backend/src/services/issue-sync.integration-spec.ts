import { DataSource, EntityManager } from 'typeorm';
import { buildFingerprint } from '../domain/issues/issue-fingerprint';
import { ENTITIES, Finding, Issue, Repository, STATE_OPEN, STATE_RESOLVED, Scan, TRIAGE_FIXED, TRIAGE_NOT_AFFECTED, TRIAGE_UNDER_REVIEW } from '../persistence/entities';
import { IssueSyncService } from './issue-sync.service';
import { connectToTestDatabase } from '../../test/database';

/**
 * Le cycle de vie des problèmes, contre une vraie base.
 *
 * Pas de base simulée ici, et pour une raison précise : ce que ce service peut casser —
 * un problème résolu à tort, un triage effacé, un `timesSeen` qui dérive — ne se voit
 * que dans les lignes qui restent après la transaction. Un test à double factice
 * vérifierait que le code fait ce qu'il fait.
 *
 * Chaque test tourne dans une transaction annulée à la fin : les cas ne se voient pas
 * entre eux, et la base reste propre pour le test de parité de schéma.
 */

describe('réconciliation des problèmes depuis un scan', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    const service = new IssueSyncService();

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    /** Un dépôt et un scan terminé, prêts à recevoir des constats. */
    async function targetWithScan(): Promise<Scan> {
        const repository = await manager.save(Object.assign(new Repository(), { url: 'git@exemple:org/projet.git', branch: 'main', subPath: null, name: null, scanIntervalMinutes: null, scanCron: null, lastScheduledScanAt: null, sshKeyId: null }));
        const repoId = repository.id;
        return manager.save(
            Object.assign(new Scan(), {
                repoId,
                containerId: null,
                branch: 'main',
                status: 'completed',
                findingsCount: 0,
                newIssuesCount: 0,
                resolvedIssuesCount: 0,
                attempts: 0,
                createdAt: new Date('2026-08-10T08:00:00Z')
            })
        );
    }

    function finding(scan: Scan, overrides: Partial<Finding> = {}): Finding {
        return Object.assign(new Finding(), {
            scanId: scan.id,
            type: 'vulnerability',
            severity: 'high',
            identifier: 'CVE-2024-1234',
            packageName: 'requests',
            packageVersion: '2.31.0',
            purl: 'pkg:pypi/requests@2.31.0',
            filePath: 'requirements.txt',
            source: 'grype',
            isKev: false,
            createdAt: new Date('2026-08-10T08:00:00Z'),
            epssScore: null,
            cvssScore: null,
            cvssVector: null,
            fixState: null,
            fixVersions: null,
            link: null,
            issueId: null,
            isDirectDependency: null,
            line: null,
            description: null,
            ...overrides
        });
    }

    const VULN = ['vulnerability'];

    it('écrit les constats, et pas seulement les problèmes', async () => {
        // Défaut vu à l'écran : le détail d'un scan annonçait huit constats et n'en
        // affichait aucun. Les problèmes portent l'histoire d'une cible ; les constats
        // disent ce qu'un scan précis a observé — matière du détail de scan, de l'export
        // SARIF, et de la preuve qu'un problème existait à une date donnée.
        const scan = await targetWithScan();
        const findings = [finding(scan, { identifier: 'CVE-2026-0001' }), finding(scan, { identifier: 'CVE-2026-0002' })];

        await service.sync(manager, scan, findings, { scannedTypes: ['vulnerability'] });

        const stored = await manager.findBy(Finding, { scanId: scan.id });
        expect(stored).toHaveLength(2);
        // Rattachés à leur problème : c'est ce qui permet de remonter d'un constat au
        // triage posé dessus.
        expect(stored.every((row) => row.issueId !== null)).toBe(true);
    });

    it('crée un problème pour un constat jamais vu', async () => {
        const scan = await targetWithScan();
        const result = await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });

        expect(result).toMatchObject({ new: 1, resolved: 0, reopened: 0, stillOpen: 0 });
        const stored = await manager.findOneByOrFail(Issue, { repoId: scan.repoId });
        expect(stored.state).toBe(STATE_OPEN);
        expect(stored.timesSeen).toBe(1);
        expect(stored.triageStatus).toBe(TRIAGE_UNDER_REVIEW);
    });

    it('rattache chaque occurrence au problème, pas seulement la première', async () => {
        // Le même CVE à deux endroits du même paquet : un problème, deux occurrences.
        const scan = await targetWithScan();
        const findings = [finding(scan), finding(scan)];
        await service.sync(manager, scan, findings, { scannedTypes: VULN });

        const stored = await manager.findOneByOrFail(Issue, { repoId: scan.repoId });
        expect(findings.map((item) => item.issueId)).toEqual([stored.id, stored.id]);
    });

    it('incrémente timesSeen au lieu de créer un doublon', async () => {
        const scan = await targetWithScan();
        await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });
        const second = await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });

        expect(second).toMatchObject({ new: 0, stillOpen: 1 });
        expect(await manager.countBy(Issue, { repoId: scan.repoId })).toBe(1);
        expect((await manager.findOneByOrFail(Issue, { repoId: scan.repoId })).timesSeen).toBe(2);
    });

    it('suit la montée de version sans perdre l’identité du problème', async () => {
        // La version est rafraîchie, mais le purl entre dans l'empreinte : deux purls
        // différents restent deux problèmes. Ce test verrouille le comportement réel.
        const scan = await targetWithScan();
        await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });
        await service.sync(manager, scan, [finding(scan, { packageVersion: '2.31.1' })], { scannedTypes: VULN });

        const stored = await manager.findOneByOrFail(Issue, { repoId: scan.repoId });
        expect(stored.packageVersion).toBe('2.31.1');
        expect(stored.timesSeen).toBe(2);
    });

    describe('résolution des disparus', () => {
        it('résout ce qui n’est plus vu par un scan qui a cherché', async () => {
            const scan = await targetWithScan();
            await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });

            const result = await service.sync(manager, scan, [], { scannedTypes: VULN });

            expect(result.resolved).toBe(1);
            const stored = await manager.findOneByOrFail(Issue, { repoId: scan.repoId });
            expect(stored.state).toBe(STATE_RESOLVED);
            expect(stored.resolvedAt).not.toBeNull();
        });

        it('ne résout RIEN quand l’étape n’a pas tourné', async () => {
            // Le cœur du contrat : « aucun constat » et « pas cherché » sont deux
            // choses différentes. Les confondre résout en silence tout un backlog de
            // sécurité, sans erreur nulle part.
            const scan = await targetWithScan();
            await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });

            const result = await service.sync(manager, scan, [], { scannedTypes: [] });

            expect(result.resolved).toBe(0);
            expect((await manager.findOneByOrFail(Issue, { repoId: scan.repoId })).state).toBe(STATE_OPEN);
        });

        it('ne résout que les types réellement cherchés', async () => {
            const scan = await targetWithScan();
            await service.sync(manager, scan, [finding(scan), finding(scan, { type: 'secret', identifier: 'aws-token', purl: null, packageName: null })], {
                scannedTypes: ['vulnerability', 'secret']
            });

            // Un scan qui ne cherche que les vulnérabilités ne doit pas toucher aux secrets.
            const result = await service.sync(manager, scan, [], { scannedTypes: VULN });

            expect(result.resolved).toBe(1);
            const secret = await manager.findOneByOrFail(Issue, { repoId: scan.repoId, type: 'secret' });
            expect(secret.state).toBe(STATE_OPEN);
        });

        it('ne touche pas aux problèmes d’une autre cible', async () => {
            const first = await targetWithScan();
            const second = await targetWithScan();
            await service.sync(manager, first, [finding(first)], { scannedTypes: VULN });

            await service.sync(manager, second, [], { scannedTypes: VULN });

            expect((await manager.findOneByOrFail(Issue, { repoId: first.repoId })).state).toBe(STATE_OPEN);
        });
    });

    describe('réouverture', () => {
        it('rouvre un problème résolu qui réapparaît', async () => {
            const scan = await targetWithScan();
            await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });
            await service.sync(manager, scan, [], { scannedTypes: VULN });

            const result = await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });

            expect(result).toMatchObject({ new: 0, reopened: 1 });
            const stored = await manager.findOneByOrFail(Issue, { repoId: scan.repoId });
            expect(stored.state).toBe(STATE_OPEN);
            expect(stored.resolvedAt).toBeNull();
        });

        it('remet sous revue un triage « fixed » factuellement contredit', async () => {
            const scan = await targetWithScan();
            await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });
            await manager.update(Issue, { repoId: scan.repoId }, { state: STATE_RESOLVED, triageStatus: TRIAGE_FIXED, triagedBy: 'alice', triagedAt: new Date('2026-07-01T10:00:00Z') });

            await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });

            const stored = await manager.findOneByOrFail(Issue, { repoId: scan.repoId });
            // Le laisser « corrigé » cacherait une régression derrière une décision périmée.
            expect(stored.triageStatus).toBe(TRIAGE_UNDER_REVIEW);
            expect(stored.triagedBy).toBeNull();
        });

        it('laisse survivre un « not_affected », qui porte sur l’exposition du code', async () => {
            const scan = await targetWithScan();
            await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });
            await manager.update(
                Issue,
                { repoId: scan.repoId },
                { state: STATE_RESOLVED, triageStatus: TRIAGE_NOT_AFFECTED, triageJustification: 'component_not_present', triagedBy: 'alice' }
            );

            await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });

            const stored = await manager.findOneByOrFail(Issue, { repoId: scan.repoId });
            expect(stored.triageStatus).toBe(TRIAGE_NOT_AFFECTED);
            expect(stored.triageJustification).toBe('component_not_present');
        });
    });

    describe('rafraîchissement partiel', () => {
        it('n’efface pas un enrichissement acquis avec une valeur nulle', async () => {
            // L'enrichissement EPSS/KEV tourne *après* la réconciliation pour un constat
            // neuf. Écraser sans condition effacerait, à chaque scan, ce que le scan
            // précédent avait établi.
            const scan = await targetWithScan();
            await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });
            await manager.update(Issue, { repoId: scan.repoId }, { epssScore: 0.42, isKev: true, cvssScore: 9.1 });

            await service.sync(manager, scan, [finding(scan, { epssScore: null, cvssScore: null })], { scannedTypes: VULN });

            const stored = await manager.findOneByOrFail(Issue, { repoId: scan.repoId });
            expect(stored.epssScore).toBe(0.42);
            expect(stored.cvssScore).toBe(9.1);
        });

        it('applique une valeur nouvellement disponible', async () => {
            const scan = await targetWithScan();
            await service.sync(manager, scan, [finding(scan)], { scannedTypes: VULN });

            await service.sync(manager, scan, [finding(scan, { fixVersions: '2.32.0', epssScore: 0.7 })], { scannedTypes: VULN });

            const stored = await manager.findOneByOrFail(Issue, { repoId: scan.repoId });
            expect(stored.fixVersions).toBe('2.32.0');
            expect(stored.epssScore).toBe(0.7);
        });
    });

    describe('hook avant commit', () => {
        it('voit le résultat pendant que la transaction est ouverte', async () => {
            const scan = await targetWithScan();
            let seenInsideTransaction: number | null = null;

            await service.sync(manager, scan, [finding(scan)], {
                scannedTypes: VULN,
                beforeCommit: async (result) => {
                    // L'outbox doit pouvoir écrire ici, et lire ce que la réconciliation
                    // vient d'écrire.
                    seenInsideTransaction = await manager.countBy(Issue, { repoId: scan.repoId });
                    expect(result.new).toBe(1);
                }
            });

            expect(seenInsideTransaction).toBe(1);
        });

        it('ne fait pas perdre les résultats du scan quand il échoue', async () => {
            const scan = await targetWithScan();

            const result = await service.sync(manager, scan, [finding(scan)], {
                scannedTypes: VULN,
                beforeCommit: () => {
                    throw new Error('webhook injoignable');
                }
            });

            expect(result.new).toBe(1);
            expect(await manager.countBy(Issue, { repoId: scan.repoId })).toBe(1);
        });
    });

    it('écrit sur le scan les compteurs que la liste des scans affiche', async () => {
        const scan = await targetWithScan();
        await service.sync(manager, scan, [finding(scan), finding(scan, { identifier: 'CVE-2024-9999' })], { scannedTypes: VULN });

        await service.sync(manager, scan, [finding(scan, { identifier: 'CVE-2025-0001' })], { scannedTypes: VULN });

        expect(scan.newIssuesCount).toBe(1);
        expect(scan.resolvedIssuesCount).toBe(2);
    });

    it('calcule la même empreinte que le domaine, sur une ligne réellement stockée', async () => {
        // Le lien entre le calcul pur et ce qui atterrit en base : c'est cette colonne
        // qui doit correspondre aux empreintes écrites par l'implémentation Python.
        const scan = await targetWithScan();
        const item = finding(scan);
        await service.sync(manager, scan, [item], { scannedTypes: VULN });

        const stored = await manager.findOneByOrFail(Issue, { repoId: scan.repoId });
        expect(stored.fingerprint).toBe(
            buildFingerprint({
                repoId: scan.repoId,
                containerId: null,
                findingType: item.type,
                identifier: item.identifier,
                purl: item.purl,
                packageName: item.packageName,
                filePath: item.filePath
            })
        );
    });
});
