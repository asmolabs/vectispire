import { DataSource, EntityManager } from 'typeorm';
import { GatePolicyRow, Issue, Repository as GitRepository, STATE_OPEN, TRIAGE_FIXED, TRIAGE_NOT_AFFECTED, TRIAGE_UNDER_REVIEW } from '../persistence/entities';
import { AuditLogService } from './audit-log.service';
import { TicketSweepService } from './ticket-sweep.service';
import { TicketService } from './ticket.service';
import type { SettingsService } from './settings.service';
import { connectToTestDatabase } from '../../test/database';

/**
 * Le balayage des tickets, contre une vraie base.
 *
 * Deux propriétés ne se voient qu'ici. **L'idempotence** : la référence posée sur le
 * problème est la clé de déduplication, donc un second passage ne doit rien rouvrir. Et
 * **l'absence de marqueur pour un problème sous la barre** : ne rien écrire est ce qui lui
 * permet de redevenir candidat le jour où la politique est durcie.
 */

function settings(values: Record<string, string> = {}): SettingsService {
    const store = {
        ticket_provider: 'gitlab',
        ticket_base_url: 'https://gitlab.exemple.test',
        ticket_project: 'groupe/projet',
        ticket_token: 'jeton',
        ...values
    };
    return {
        get: async (key: string, fallback = '') => store[key] ?? fallback,
        set: async () => {},
        isEnabled: async (key: string, fallback: boolean) => (store[key] ?? (fallback ? 'true' : 'false')) === 'true',
        all: async () => ({ ...store })
    } as unknown as SettingsService;
}

describe('balayage des tickets', () => {
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

    /** Le service, avec un gestionnaire simulé qui compte ses appels. */
    function sweeper(overrides: Record<string, string> = {}) {
        const opened: string[] = [];
        let counter = 0;
        const post = async (url: string) => {
            opened.push(url);
            counter += 1;
            return { iid: counter, web_url: `https://gitlab.exemple.test/-/issues/${counter}` };
        };
        const tickets = new TicketService(settings(overrides), null, post);
        return { opened, service: new TicketSweepService(manager, tickets, new AuditLogService()) };
    }

    async function repository(): Promise<GitRepository> {
        return manager.save(
            Object.assign(new GitRepository(), {
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
    }

    /**
     * Une politique globale complète.
     *
     * **Toutes les colonnes obligatoires sont posées ici, en un seul endroit.** Les
     * remplir au cas par cas dans chaque test a coûté trois passages de campagne, chacun
     * révélant une colonne NOT NULL de plus — `fixableOnly`, puis `includeAiReview`. Un
     * défaut d'entité les couvrirait aussi, mais il masquerait alors ce qu'une politique
     * dit réellement.
     */
    async function globalPolicy(values: Partial<GatePolicyRow> = {}): Promise<GatePolicyRow> {
        return manager.save(
            Object.assign(new GatePolicyRow(), {
                targetKind: 'global',
                targetId: 0,
                version: 1,
                isActive: true,
                failOnSeverity: 'critical',
                failOnKev: false,
                fixableOnly: false,
                includeTriaged: false,
                includeAiReview: false,
                note: null,
                createdBy: null,
                createdAt: new Date(),
                ...values
            })
        );
    }

    async function issue(repoId: number, values: Partial<Issue> = {}): Promise<Issue> {
        return manager.save(
            Object.assign(new Issue(), {
                repoId,
                containerId: null,
                fingerprint: `empreinte-${Math.random()}`,
                type: 'vulnerability',
                identifier: 'CVE-2021-44228',
                severity: 'critical',
                state: STATE_OPEN,
                triageStatus: TRIAGE_UNDER_REVIEW,
                isKev: false,
                timesSeen: 1,
                firstSeenAt: new Date(),
                lastSeenAt: new Date(),
                ticketRef: null,
                ticketUrl: null,
                ...values
            })
        );
    }

    it('ouvre un ticket et enregistre sa référence', async () => {
        const repo = await repository();
        const created = await issue(repo.id);
        const { service } = sweeper();

        expect(await service.sweep()).toBe(1);

        const row = await manager.findOneByOrFail(Issue, { id: created.id });
        expect(row.ticketRef).toBe('#1');
        expect(row.ticketUrl).toContain('/-/issues/1');
    });

    it("n'ouvre pas un second ticket au passage suivant", async () => {
        // La référence *est* la clé de déduplication : un ticket qui revient d'entre les
        // morts à chaque rescan est la façon dont les gens apprennent à couper un projet.
        const repo = await repository();
        await issue(repo.id);
        const { opened, service } = sweeper();

        await service.sweep();
        expect(await service.sweep()).toBe(0);
        expect(opened).toHaveLength(1);
    });

    it('écarte les problèmes triés comme sans objet', async () => {
        const repo = await repository();
        await issue(repo.id, { triageStatus: TRIAGE_NOT_AFFECTED });
        await issue(repo.id, { triageStatus: TRIAGE_FIXED });
        const { service } = sweeper();

        expect(await service.sweep()).toBe(0);
    });

    it("laisse un problème sous la barre sans marqueur, pour qu'il redevienne candidat", async () => {
        // Le point subtil : ne rien écrire est ce qui lui permet d'être repris le jour où
        // la politique est durcie. Poser un marqueur l'exclurait pour toujours.
        const repo = await repository();
        const low = await issue(repo.id, { severity: 'low' });
        await globalPolicy({ failOnSeverity: 'critical' });
        const { service } = sweeper();

        expect(await service.sweep()).toBe(0);
        expect((await manager.findOneByOrFail(Issue, { id: low.id })).ticketRef).toBeNull();
    });

    it('honore le plafond par passage', async () => {
        // Un premier passage sur un backlog mature ouvrirait sinon des centaines de tickets
        // d'un coup — un problème de débit, et surtout un problème social.
        const repo = await repository();
        for (let index = 0; index < 5; index += 1) await issue(repo.id);
        const { service } = sweeper();

        expect(await service.sweep(3)).toBe(3);
    });

    it('sert le plus grave en premier quand le plafond mord', async () => {
        const repo = await repository();
        const faible = await issue(repo.id, { severity: 'low', identifier: 'CVE-FAIBLE' });
        const grave = await issue(repo.id, { severity: 'critical', identifier: 'CVE-GRAVE' });
        const { service } = sweeper();

        await service.sweep(1);

        expect((await manager.findOneByOrFail(Issue, { id: grave.id })).ticketRef).not.toBeNull();
        expect((await manager.findOneByOrFail(Issue, { id: faible.id })).ticketRef).toBeNull();
    });

    it('ne fait rien quand le gestionnaire n\'est pas configuré', async () => {
        const repo = await repository();
        await issue(repo.id);
        const { opened, service } = sweeper({ ticket_token: '' });

        expect(await service.sweep()).toBe(0);
        expect(opened).toEqual([]);
    });
});
