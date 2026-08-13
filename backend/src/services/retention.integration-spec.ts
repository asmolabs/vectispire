import { DataSource, EntityManager } from 'typeorm';
import { Repository, Scan, STATUS_COMPLETED } from '../persistence/entities';
import { RetentionService } from './retention.service';
import type { SettingsService } from './settings.service';
import { connectToTestDatabase } from '../../test/database';

/**
 * La rétention, contre une vraie base.
 *
 * **Le défaut que ce fichier existe pour attraper n'est visible qu'à l'exécution** : sur
 * une colonne JSON, écrire `null` peut produire le littéral JSON `null` plutôt qu'un NULL
 * SQL. La ligne satisfait alors `IS NOT NULL`, donc chaque passage de la purge la
 * re-sélectionne, la « purge » à nouveau, et ne libère jamais rien — tout en rapportant
 * un nombre de scans purgés parfaitement crédible. La pile Python portait exactement ce
 * défaut, sous le nom de `none_as_null`.
 */

function settings(values: Record<string, string> = {}): SettingsService {
    return { get: async (key: string, fallback = '') => values[key] ?? fallback } as unknown as SettingsService;
}

describe('rétention des charges brutes', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;

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

    /** Un dépôt et `count` scans porteurs de charges, du plus ancien au plus récent. */
    async function repositoryWithScans(count: number, ageDays: (index: number) => number): Promise<{ repoId: number; ids: number[] }> {
        const repository = await manager.save(
            Object.assign(new Repository(), {
                url: 'git@exemple:org/projet.git',
                branch: 'main',
                subPath: null,
                name: null,
                scanIntervalMinutes: null,
                scanCron: null,
                lastScheduledScanAt: null,
                sshKeyId: null
            })
        );

        const ids: number[] = [];
        for (let index = 0; index < count; index += 1) {
            const scan = await manager.save(
                Object.assign(new Scan(), {
                    repoId: repository.id,
                    containerId: null,
                    branch: 'main',
                    subPath: null,
                    status: STATUS_COMPLETED,
                    sbom: { artifacts: [{ name: `paquet-${index}` }] },
                    cves: [{ id: `CVE-${index}` }],
                    summary: { critical: 0 },
                    createdAt: new Date(Date.now() - ageDays(index) * 86_400_000),
                    findingsCount: 0,
                    newIssuesCount: 0,
                    resolvedIssuesCount: 0,
                    attempts: 0
                })
            );
            ids.push(scan.id);
        }
        return { repoId: repository.id, ids };
    }

    it('écrit un NULL SQL et non le littéral JSON null', async () => {
        // Le cœur du fichier : après une purge, un second passage ne doit plus rien voir.
        const { ids } = await repositoryWithScans(3, () => 400);
        const service = new RetentionService(manager, settings({ retention_keep_per_target: '0', retention_max_age_days: '90' }));

        expect((await service.prune(manager)).scansPruned).toBe(3);
        expect(await service.findPrunable(manager)).toEqual([]);
        expect(await service.payloadCount(manager)).toBe(0);

        const row = await manager.findOneByOrFail(Scan, { id: ids[0] });
        expect(row.sbom).toBeNull();
        expect(row.cves).toBeNull();
    });

    it("garde toujours les N derniers scans d'une cible, quel que soit leur âge", async () => {
        // Une politique qui laisserait tomber les charges les plus récentes serait inutile
        // pour la seule chose à quoi elles servent.
        const { ids } = await repositoryWithScans(5, () => 400);
        const service = new RetentionService(manager, settings({ retention_keep_per_target: '2', retention_max_age_days: '90' }));

        const prunable = await service.findPrunable(manager);

        // Les identifiants croissent avec le temps de création décroissant : les deux
        // premiers créés sont les plus récents pour la base, mais tous ont le même âge —
        // ce qui compte ici est qu'il en reste exactement deux.
        expect(prunable).toHaveLength(3);
        expect(ids).toEqual(expect.arrayContaining(prunable));
    });

    it('ne purge que ce qui est à la fois hors fenêtre et assez vieux', async () => {
        // Les deux règles se conjuguent : une cible scannée deux fois par an garde ses
        // charges même hors de la fenêtre des N derniers.
        await repositoryWithScans(5, () => 10);
        const service = new RetentionService(manager, settings({ retention_keep_per_target: '2', retention_max_age_days: '90' }));

        expect(await service.findPrunable(manager)).toEqual([]);
    });

    it('ne purge rien quand les deux axes sont à zéro', async () => {
        await repositoryWithScans(5, () => 400);
        const service = new RetentionService(manager, settings({ retention_keep_per_target: '0', retention_max_age_days: '0' }));

        expect(await service.findPrunable(manager)).toEqual([]);
        expect((await service.prune(manager)).scansPruned).toBe(0);
    });

    it('retombe sur les défauts quand un réglage est illisible', async () => {
        // Zéro veut dire « aucune limite » : une faute de frappe qui se lirait zéro
        // désactiverait la rétention en silence et la base recommencerait à grossir.
        const service = new RetentionService(manager, settings({ retention_keep_per_target: 'dix', retention_max_age_days: '' }));

        expect(await service.policy()).toEqual({ keepPerTarget: 10, maxAgeDays: 90 });
    });

    it("laisse intacts les constats et l'historique du scan purgé", async () => {
        // La projection normalisée *est* le registre durable : purger un bloc ne doit
        // coûter ni historique, ni delta.
        const { ids } = await repositoryWithScans(1, () => 400);
        const service = new RetentionService(manager, settings({ retention_keep_per_target: '0', retention_max_age_days: '90' }));

        await service.prune(manager);

        const row = await manager.findOneByOrFail(Scan, { id: ids[0] });
        expect(row.summary).toEqual({ critical: 0 });
        expect(row.status).toBe(STATUS_COMPLETED);
    });
});
