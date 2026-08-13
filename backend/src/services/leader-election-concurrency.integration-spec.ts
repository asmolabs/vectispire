import { DataSource } from 'typeorm';
import { connectToTestDatabase } from '../../test/database';
import { LEASE_SECONDS, LeaderElectionService } from './leader-election.service';

/**
 * L'élection de meneur sous **vraie** concurrence — dans son propre fichier, sans
 * transaction englobante.
 *
 * Les autres cas tournent dans une transaction annulée, ce qui les isole mais les
 * sérialise : deux appels y passent par la même connexion, l'un après l'autre. Ils
 * vérifient la logique conditionnelle, pas la course.
 *
 * Or la course *est* la conception. La primitive est un `UPDATE` conditionnel dont le
 * nombre de lignes touchées désigne le gagnant, et la seule question qui compte est ce
 * qu'elle fait quand dix connexions distinctes visent la même ligne au même instant. Un
 * `UPDATE` inconditionnel passerait tous les tests sérialisés et donnerait le bail à tout
 * le monde en production — chaque instance dépêchant les mêmes cibles, chaque cible
 * scannée autant de fois qu'il y a d'instances.
 */
const JOB = 'concurrence-scheduler';

describe('élection de meneur — concurrence', () => {
    let dataSource: DataSource;

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 30_000);

    /** Hors transaction : c'est le sujet même de ce bloc. */
    async function withOwnLease<T>(body: () => Promise<T>): Promise<T> {
        await dataSource.query('DELETE FROM t_leader_lease WHERE name = $1', [JOB]);
        try {
            return await body();
        } finally {
            await dataSource.query('DELETE FROM t_leader_lease WHERE name = $1', [JOB]);
        }
    }

    /** Une instance = un service sur son propre gestionnaire, comme un processus distinct. */
    function instances(count: number): LeaderElectionService[] {
        return Array.from({ length: count }, () => new LeaderElectionService(dataSource.manager));
    }

    it('un seul gagnant quand dix instances démarrent ensemble', async () => {
        // La toute première acquisition : c'est la clé primaire qui arbitre, et les
        // perdantes doivent attraper la violation de contrainte plutôt que de la propager.
        await withOwnLease(async () => {
            const at = new Date();
            const results = await Promise.all(instances(10).map((service, index) => service.acquire(JOB, `instance-${index}`, at)));

            expect(results.filter(Boolean)).toHaveLength(1);
            expect(await instances(1)[0].currentHolder(JOB, at)).toMatch(/^instance-\d$/);
        });
    });

    it('un seul gagnant quand dix instances se disputent un bail expiré', async () => {
        // Le second chemin, et le plus subtil : la ligne existe, toutes la lisent expirée,
        // toutes tentent de la prendre. La condition sur l'expiration lue est ce qui fait
        // perdre les neuf autres.
        await withOwnLease(async () => {
            const start = new Date();
            await instances(1)[0].acquire(JOB, 'sortante', start);

            const expired = new Date(start.getTime() + (LEASE_SECONDS + 1) * 1000);
            const results = await Promise.all(instances(10).map((service, index) => service.acquire(JOB, `reprise-${index}`, expired)));

            expect(results.filter(Boolean)).toHaveLength(1);
            expect(await instances(1)[0].currentHolder(JOB, expired)).toMatch(/^reprise-\d$/);
        });
    });

    it('le détenteur garde son bail malgré neuf prétendants simultanés', async () => {
        // Le cas qui compte le plus en exploitation : un meneur bien vivant ne doit jamais
        // se faire souffler le travail, sinon il tourne dans la flotte sans raison.
        await withOwnLease(async () => {
            const at = new Date();
            const [holder, ...challengers] = instances(10);
            await holder.acquire(JOB, 'titulaire', at);

            const results = await Promise.all([
                holder.acquire(JOB, 'titulaire', new Date(at.getTime() + 1000)),
                ...challengers.map((service, index) => service.acquire(JOB, `prétendant-${index}`, new Date(at.getTime() + 1000)))
            ]);

            expect(results[0]).toBe(true);
            expect(results.slice(1).filter(Boolean)).toHaveLength(0);
            expect(await holder.currentHolder(JOB, new Date(at.getTime() + 1000))).toBe('titulaire');
        });
    });
});
