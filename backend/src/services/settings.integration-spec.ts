import { DataSource, EntityManager } from 'typeorm';
import { Setting } from '../persistence/entities';
import { SettingsService } from './settings.service';
import { connectToTestDatabase } from '../../test/database';

/**
 * Les réglages, contre une vraie base.
 *
 * Deux comportements ne se voient qu'ici : qu'une réécriture de la même clé fusionne au
 * lieu d'échouer sur la clé primaire, et qu'une valeur vide délibérément posée reste vide
 * au lieu de retomber sur le défaut du lecteur.
 */
describe('réglages', () => {
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

    function settings(): SettingsService {
        return new SettingsService(manager);
    }

    it('rend le défaut pour une clé absente', async () => {
        expect(await settings().get('jamais_reglee', 'défaut')).toBe('défaut');
        expect(await settings().isEnabled('jamais_reglee', true)).toBe(true);
        expect(await settings().isEnabled('jamais_reglee', false)).toBe(false);
    });

    it('écrit puis relit', async () => {
        const service = settings();
        await service.set('notification_min_severity', 'critical');

        expect(await service.get('notification_min_severity')).toBe('critical');
    });

    it('fusionne une réécriture au lieu de heurter la clé primaire', async () => {
        // Deux requêtes concurrentes sur la même clé feraient échouer la seconde insertion
        // avec un « lire puis écrire » ; l'upsert est ce qui rend l'écriture rejouable.
        const service = settings();
        await service.set('notification_min_severity', 'critical');
        await service.set('notification_min_severity', 'medium');

        expect(await service.get('notification_min_severity')).toBe('medium');
        expect(await manager.countBy(Setting, { key: 'notification_min_severity' })).toBe(1);
    });

    it('conserve une valeur vide posée délibérément', async () => {
        // `?? défaut` et non `|| défaut` : effacer une URL de webhook doit désactiver les
        // notifications, pas restaurer une valeur que personne n'a demandée.
        const service = settings();
        await service.set('notification_webhook_url', '');

        expect(await service.get('notification_webhook_url', 'https://defaut.test/')).toBe('');
    });

    it("ne considère activé que la chaîne « true »", async () => {
        const service = settings();
        await service.set('enrichment_enabled', 'oui');

        expect(await service.isEnabled('enrichment_enabled', true)).toBe(false);
    });

    it('rend toutes les valeurs en une carte', async () => {
        const service = settings();
        await service.set('enrichment_enabled', 'false');
        await service.set('eol_warn_days', '30');

        const all = await service.all();
        expect(all.enrichment_enabled).toBe('false');
        expect(all.eol_warn_days).toBe('30');
    });
});
