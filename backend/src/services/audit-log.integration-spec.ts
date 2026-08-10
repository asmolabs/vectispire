import { DataSource, EntityManager } from 'typeorm';
import { computeEntryHash } from '../domain/audit/audit-hash';
import { ENTITIES } from '../persistence/entities';
import { configurePostgresTypeParsers } from '../persistence/pg-types';
import { AuditLogService } from './audit-log.service';

/**
 * Le journal d'audit contre une vraie base.
 *
 * C'est ici que se vérifie la seconde moitié de la chaîne d'horodatage : une entrée
 * écrite, relue, et dont l'empreinte se recalcule à l'identique. Le maillon manquant
 * serait invisible autrement — TypeORM ré-hydrate les colonnes de date en `Date` et
 * décale de l'offset local, ce qui ferait échouer chaque entrée à sa propre
 * vérification sur toute machine qui n'est pas en UTC.
 */
const connectionString = process.env.ZANSHIN_TEST_DATABASE_URL;
const describeWithPostgres = connectionString ? describe : describe.skip;

describeWithPostgres('journal d’audit', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    const service = new AuditLogService();

    beforeAll(async () => {
        configurePostgresTypeParsers();
        dataSource = new DataSource({ type: 'postgres', url: connectionString, entities: ENTITIES, synchronize: false });
        await dataSource.initialize();
    }, 30_000);

    afterAll(async () => {
        if (dataSource?.isInitialized) await dataSource.destroy();
    });

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
        // La table est partagée : on repart d'un journal vide pour que la chaîne
        // vérifiée soit celle que le test vient d'écrire.
        await manager.query('DELETE FROM audit_logs');
    });

    afterEach(async () => release());

    const entry = (over = {}) => ({ operationType: 'SETTING_UPDATED', resourceId: 'sast_enabled', description: 'Réglage modifié', userId: 'admin', ...over });

    it('écrit une entrée et la chaîne se vérifie', async () => {
        await service.record(manager, entry());
        expect(await service.verify(manager)).toEqual({ broken: null, unverifiable: 0 });
    });

    it("recalcule à l'identique l'empreinte d'une entrée relue", async () => {
        // Le test qui compte : écriture, relecture, recalcul. C'est lui qui échouerait
        // si un maillon décalait l'horodatage ou en perdait la précision.
        await service.record(manager, entry());

        const [stored] = await service.findRecent(manager);

        expect(typeof stored.timestamp).toBe('string');
        expect(computeEntryHash(stored)).toBe(stored.entryHash);
    });

    it('chaîne les entrées dans leur ordre d’écriture', async () => {
        for (let i = 0; i < 5; i += 1) await service.record(manager, entry({ resourceId: String(i) }));

        const chained = await service.verify(manager);

        expect(chained).toEqual({ broken: null, unverifiable: 0 });
        const recent = await service.findRecent(manager);
        expect(recent).toHaveLength(5);
        expect(recent[recent.length - 1].previousHash).toBeNull();
    });

    it('détecte une entrée modifiée après coup', async () => {
        for (let i = 0; i < 3; i += 1) await service.record(manager, entry({ resourceId: String(i) }));
        await manager.query("UPDATE audit_logs SET description = 'réécrit' WHERE resource_id = '1'");

        expect((await service.verify(manager)).broken).toContain('ne correspond plus');
    });

    it('détecte une entrée supprimée', async () => {
        for (let i = 0; i < 3; i += 1) await service.record(manager, entry({ resourceId: String(i) }));
        await manager.query("DELETE FROM audit_logs WHERE resource_id = '1'");

        expect((await service.verify(manager)).broken).toContain('modifiée ou supprimée');
    });

    it('ne fait pas échouer l’action qu’il décrit quand il ne peut pas écrire', async () => {
        // Le contraire donnerait à une table pleine le pouvoir d'empêcher un
        // administrateur de se connecter.
        await expect(service.record(manager, entry({ operationType: 'x'.repeat(500) }))).resolves.toBeUndefined();
    });

    it('tronque une description trop longue plutôt que de perdre l’entrée', async () => {
        await service.record(manager, entry({ description: 'é'.repeat(400) }));

        const [stored] = await service.findRecent(manager);
        expect(stored.description).toHaveLength(255);
        expect(computeEntryHash(stored)).toBe(stored.entryHash);
    });

    describe('reconstruction de la chaîne', () => {
        it('rend vérifiable un historique venu d’une autre formule', async () => {
            for (let i = 0; i < 4; i += 1) await service.record(manager, entry({ resourceId: String(i) }));
            // Ce que laisse l'implémentation Python : des empreintes cohérentes entre
            // elles, et fausses pour la formule d'ici.
            await manager.query("UPDATE audit_logs SET entry_hash = 'ancienne-' || resource_id, previous_hash = NULL");
            expect((await service.verify(manager)).broken).not.toBeNull();

            expect(await service.rebuild(manager)).toBe(4);

            expect(await service.verify(manager)).toEqual({ broken: null, unverifiable: 0 });
        });

        it('ne touche pas au contenu', async () => {
            await service.record(manager, entry({ description: 'Texte à préserver' }));
            await service.rebuild(manager);

            const [stored] = await service.findRecent(manager);
            expect(stored.description).toBe('Texte à préserver');
        });

        it('est idempotente', async () => {
            for (let i = 0; i < 3; i += 1) await service.record(manager, entry({ resourceId: String(i) }));
            await service.rebuild(manager);
            const once = (await service.findRecent(manager)).map((row) => row.entryHash);

            await service.rebuild(manager);

            expect((await service.findRecent(manager)).map((row) => row.entryHash)).toEqual(once);
        });
    });
});
