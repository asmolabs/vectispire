import { DataSource, EntityManager } from 'typeorm';
import { ENTITIES } from '../persistence/entities';
import { AuditLogService } from '../services/audit-log.service';
import { AuditLogController } from './audit-log.controller';
import { connectToTestDatabase } from '../../test/database';


describe("API du journal d'audit", () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    let controller: AuditLogController;
    const audit = new AuditLogService();

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        controller = new AuditLogController(manager);
        await manager.query('DELETE FROM t_audit_log');
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    async function record(operationType: string, description: string, userId = 'admin'): Promise<void> {
        await audit.record(manager, { operationType, resourceId: '1', description, userId, ipAddress: '127.0.0.1' });
    }

    it('déclare intacte une chaîne qu’il vient de construire', async () => {
        for (let index = 0; index < 5; index++) await record('SETTING_UPDATED', `entrée ${index}`);

        const result = await controller.verify();
        expect(result.intact).toBe(true);
        expect(result.broken).toBeNull();
        expect(result.total).toBe(5);
        expect(result.unverifiable).toBe(0);
    });

    it('détecte une entrée dont la description a été modifiée en base', async () => {
        for (let index = 0; index < 4; index++) await record('SETTING_UPDATED', `entrée ${index}`);
        // Exactement ce que le journal existe pour révéler : une écriture directe.
        await manager.query("UPDATE t_audit_log SET description = 'réécrite' WHERE description = 'entrée 2'");

        const result = await controller.verify();
        expect(result.intact).toBe(false);
        expect(result.broken).toBeTruthy();
    });

    it('détecte une entrée supprimée au milieu', async () => {
        for (let index = 0; index < 4; index++) await record('SETTING_UPDATED', `entrée ${index}`);
        await manager.query("DELETE FROM t_audit_log WHERE description = 'entrée 2'");

        expect((await controller.verify()).intact).toBe(false);
    });

    it('rend les entrées les plus récentes en premier', async () => {
        for (let index = 0; index < 3; index++) await record('SETTING_UPDATED', `entrée ${index}`);

        const page = await controller.list();
        expect(page.items[0].description).toBe('entrée 2');
        expect(page.total).toBe(3);
    });

    it('filtre par type d’opération et par utilisateur', async () => {
        await record('SETTING_UPDATED', 'un réglage', 'claire');
        await record('ACCESS_DENIED', 'un refus', 'admin');

        expect((await controller.list('ACCESS_DENIED')).total).toBe(1);
        expect((await controller.list(undefined, 'claire')).items[0].description).toBe('un réglage');
    });

    it('cherche dans la description sans que « % » ne rende tout', async () => {
        await record('SETTING_UPDATED', 'dépôt org/api ajouté');
        await record('SETTING_UPDATED', 'dépôt org/frontend ajouté');

        expect((await controller.list(undefined, undefined, 'org/api')).total).toBe(1);
        // Sans échappement, ce motif rendrait les deux lignes.
        expect((await controller.list(undefined, undefined, '%')).total).toBe(0);
    });

    it('pagine, et borne la taille de page demandée', async () => {
        for (let index = 0; index < 7; index++) await record('SETTING_UPDATED', `entrée ${index}`);

        const first = await controller.list(undefined, undefined, undefined, '3', '0');
        expect(first.items).toHaveLength(3);
        expect(first.total).toBe(7);

        const third = await controller.list(undefined, undefined, undefined, '3', '6');
        expect(third.items).toHaveLength(1);

        // Une page de 10 000 tiendrait la base et la mémoire du navigateur.
        expect((await controller.list(undefined, undefined, undefined, '10000', '0')).limit).toBe(200);
    });

    it('ne propose que les types réellement présents', async () => {
        await record('ACCESS_DENIED', 'un refus');
        expect(await controller.operationTypes()).toEqual(['ACCESS_DENIED']);
    });

    it('déclare intacte une chaîne vide plutôt que rompue', async () => {
        const result = await controller.verify();
        expect(result.intact).toBe(true);
        expect(result.total).toBe(0);
    });
});
