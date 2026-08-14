import { DataSource, EntityManager } from 'typeorm';
import { connectToTestDatabase } from '../../test/database';
import { now } from '../domain/common/timestamp';
import { Repository as GitRepository, Scan, STATUS_QUEUED } from '../persistence/entities';
import { ScanRepository } from './scan.repository';

/**
 * Le ciblage d'un scan vers un agent, contre une vraie base.
 *
 * **Ce filtre vit dans la requête verrouillante, donc il ne se teste pas ailleurs.** Il
 * s'écrit différemment selon qu'un agent porte des étiquettes ou non — `IS NULL` seul d'un
 * côté, `IS NULL OR IN (…)` de l'autre — et les deux formes doivent cohabiter avec
 * `FOR UPDATE SKIP LOCKED` sur les deux moteurs. Un faux dépôt en mémoire dirait que la
 * règle est juste sans rien prouver de la requête qui l'applique.
 *
 * Ce que ces tests protègent : un agent posé dans un segment de moindre confiance — parce
 * qu'il doit y atteindre un dépôt, ce qui est la raison d'exister des agents distants — ne
 * doit pas pouvoir réclamer les scans de tous les autres dépôts, ni recevoir leurs clés.
 */
describe('ciblage de la file', () => {
    let dataSource: DataSource;
    let manager: EntityManager;
    let release: () => Promise<void>;
    const scans = new ScanRepository();

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    beforeEach(async () => {
        const runner = dataSource.createQueryRunner();
        await runner.connect();
        await runner.startTransaction();
        manager = runner.manager;
        await manager.query('DELETE FROM t_scan');
        await manager.query('DELETE FROM t_repository');
        release = async () => {
            await runner.rollbackTransaction();
            await runner.release();
        };
    });

    afterEach(async () => release());

    /** Un scan en file, portant l'exigence donnée. */
    async function queue(requiredAgentLabel: string | null, at = now()): Promise<Scan> {
        const repository = await manager.save(
            GitRepository,
            Object.assign(new GitRepository(), { url: `https://exemple/${Math.random().toString(36).slice(2)}.git`, branch: 'main', requiredAgentLabel })
        );
        return manager.save(
            Scan,
            Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: STATUS_QUEUED, requiredAgentLabel, createdAt: at })
        );
    }

    it('confie un scan exigeant à l’agent qui porte l’étiquette', async () => {
        const scan = await queue('client');

        const claimed = await scans.claim(manager, 5, 'agent-client', ['client', 'prod']);

        expect(claimed.map((c) => c.id)).toEqual([scan.id]);
    });

    it('ne le confie pas à un agent qui ne la porte pas', async () => {
        // **Le cœur du sujet.** Sans ce filtre, l'agent de moindre confiance réclamait ce
        // scan et en recevait la clé de déploiement.
        await queue('client');

        expect(await scans.claim(manager, 5, 'agent-prod', ['prod'])).toEqual([]);
    });

    it('ne le confie pas non plus à un agent sans étiquette', async () => {
        // « Aucune étiquette veut dire toutes » est la lecture séduisante, et elle rendrait
        // l'exigence inopérante au premier agent qu'on enregistre sans y penser.
        await queue('client');

        expect(await scans.claim(manager, 5, 'agent-nu', [])).toEqual([]);
    });

    it('laisse un scan sans exigence à n’importe quel agent', async () => {
        // Le comportement d'avant, préservé : l'exiger rétroactivement arrêterait toutes
        // les files existantes au premier déploiement.
        const libre = await queue(null);

        expect((await scans.claim(manager, 5, 'agent-nu', [])).map((c) => c.id)).toEqual([libre.id]);
    });

    it('sert le travail libre sans se bloquer sur un scan qui ne lui est pas destiné', async () => {
        // **Le défaut qui aurait été silencieux.** Le scan réservé est le plus ancien : un
        // filtre appliqué *après* la sélection l'aurait pris, rendu, et l'agent serait
        // reparti les mains vides alors que du travail l'attendait — indéfiniment, puisque
        // l'ordre de la file ne change pas.
        const reserve = await queue('client', new Date(Date.now() - 60_000));
        const libre = await queue(null);

        const claimed = await scans.claim(manager, 5, 'agent-prod', ['prod']);

        expect(claimed.map((c) => c.id)).toEqual([libre.id]);
        expect(claimed.map((c) => c.id)).not.toContain(reserve.id);
    });

    it('sert plusieurs étiquettes à la fois, dans l’ordre de la file', async () => {
        const ancien = await queue('client', new Date(Date.now() - 60_000));
        const recent = await queue('prod');

        const claimed = await scans.claim(manager, 5, 'agent-double', ['client', 'prod']);

        expect(claimed.map((c) => c.id)).toEqual([ancien.id, recent.id]);
    });
});
