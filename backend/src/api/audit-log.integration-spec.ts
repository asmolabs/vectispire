import { randomUUID } from 'node:crypto';
import { DataSource, EntityManager } from 'typeorm';
import { computeEntryHash } from '../domain/audit/audit-hash';
import { AuditLog, ENTITIES } from '../persistence/entities';
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

    it("n'a pas besoin de relire tout le journal pour écrire une entrée", async () => {
        // **Mesuré avant d'être corrigé : 1,6 ms sur 200 entrées, 17,1 ms sur 3 000.**
        // Chaque écriture suivait la chaîne maillon par maillon depuis le début, donc
        // chargeait la table entière — et une écriture d'audit accompagne chaque connexion,
        // chaque triage, chaque changement de réglage. À cent mille entrées, ordinaire au
        // bout de quelques mois sur une installation active, chaque action auditée aurait
        // traîné une demi-seconde.
        //
        // Assertion sur la **forme de la requête** et non sur une durée : un test de temps
        // serait instable sur une machine chargée, et celui-ci dit exactement ce qui compte.
        for (let index = 0; index < 5; index += 1) await record('X', `entrée ${index}`);

        const requests: (Record<string, unknown> | undefined)[] = [];
        const observed = new Proxy(manager, {
            get(target, property, receiver) {
                if (property !== 'find') return Reflect.get(target, property, receiver);
                return (entity: unknown, options?: Record<string, unknown>) => {
                    requests.push(options);
                    return (target.find as (e: unknown, o?: unknown) => unknown)(entity, options);
                };
            }
        });

        await audit.record(observed, { operationType: 'X', resourceId: '1', description: 'mesurée' });

        expect(requests.length).toBeGreaterThan(0);
        // Aucune lecture sans borne : c'est ce qui distingue un coût constant d'un coût
        // proportionnel à l'histoire de l'installation.
        expect(requests.every((options) => typeof options?.take === 'number')).toBe(true);
    });

    it('déclare intact un journal fourché, comme en produit une écriture concurrente', async () => {
        // **La fausse alerte que ce changement supprime.** Deux instances web lisent la même
        // queue au même instant et produisent deux entrées portant la même précédente. La
        // vérification exigeait une file strictement unique et déclarait rompu un journal
        // parfaitement honnête — et une alerte fausse dans un contrôle d'intégrité finit par
        // couvrir les vraies.
        //
        // **La fourche est construite, et non provoquée.** Une première version lançait deux
        // connexions réelles en parallèle : sous charge elles se sérialisaient, la seconde
        // voyait la première, et le test passait sans jamais fourcher — il s'est mis à
        // échouer en campagne, sur son *propre* postulat. Ce qui compte ici est que `verify`
        // accepte cette forme contre une vraie base, pas de gagner une course.
        await record('BASE', 'entrée commune');
        const tail = (await manager.find(AuditLog, { order: { timestamp: 'DESC' }, take: 1 }))[0];

        for (const suffix of ['a', 'b']) {
            const row = {
                id: randomUUID(),
                timestamp: new Date(tail.timestamp!.getTime() + 1),
                operationType: 'CONCURRENT',
                resourceId: suffix,
                description: `écrite par l'instance ${suffix}`,
                userId: 'admin',
                ipAddress: null,
                userAgent: null,
                // Les deux descendent du même maillon : c'est exactement ce que produisent
                // deux instances ayant lu la queue avant que l'autre n'écrive.
                previousHash: tail.entryHash,
                entryHash: null as string | null
            };
            row.entryHash = computeEntryHash(row);
            await manager.save(AuditLog, Object.assign(new AuditLog(), row));
        }

        const branches = await manager.findBy(AuditLog, { operationType: 'CONCURRENT' });
        expect(branches.length).toBe(2);
        expect(branches[0].previousHash).toBe(branches[1].previousHash);

        expect((await audit.verify(manager)).broken).toBeNull();
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
