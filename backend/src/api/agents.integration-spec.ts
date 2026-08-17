import { BadRequestException, ConflictException, PreconditionFailedException, UnauthorizedException } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { connectToTestDatabase } from '../../test/database';
import { CONTRACT_VERSION } from '../domain/agents/contract';
import { now } from '../domain/common/timestamp';
import {
    Agent,
    CREDENTIALS_DELEGATED,
    CREDENTIALS_LOCAL,
    KIND_REMOTE,
    Repository as GitRepository,
    Scan,
    SshKey,
    STATUS_QUEUED
} from '../persistence/entities';
import { encryptWith, deriveKey, privateKeyContext } from '../domain/crypto/encryption';
import { generateEphemeralKeyPair, isSealed, open as openEnvelope } from '../domain/crypto/sealed-envelope';
import { EncryptionService } from '../services/encryption.service';
import { ScanDispatcherService } from '../services/scan-dispatcher.service';
import { AgentsController } from './agents.controller';
import { RuleSetService } from '../services/rule-set.service';
import type { AuthenticatedRequest } from './auth.guard';

const KEY = 'cle-de-chiffrement-de-test-32oct';
const PRIVATE = '-----BEGIN OPENSSH PRIVATE KEY-----\nfaux\n-----END OPENSSH PRIVATE KEY-----\n';

/**
 * Le protocole d'agent.
 *
 * Ce qui compte ici n'est pas le format des messages mais **les refus** : un contrat
 * incompatible, un bail repris, une clé de déploiement qui partirait en clair. Chacun
 * protège quelque chose qu'une réponse permissive détruirait en silence.
 */
describe("protocole d'agent", () => {
    let dataSource: DataSource;
    let controller: AgentsController;
    let dispatcher: ScanDispatcherService;

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
        dispatcher = new ScanDispatcherService(dataSource, undefined, undefined, undefined, new EncryptionService(KEY, []));
        controller = new AgentsController(dataSource.manager, dataSource, dispatcher, new RuleSetService(dataSource));
    }, 30_000);

    beforeEach(async () => {
        await dataSource.query('DELETE FROM t_scan');
        await dataSource.query('DELETE FROM t_repository');
        await dataSource.query('DELETE FROM t_agent');
        await dataSource.query('DELETE FROM t_ssh_key');
    });

    async function seedAgent(credentialsMode = CREDENTIALS_LOCAL, enabled = true): Promise<Agent> {
        return dataSource.manager.save(
            Agent,
            Object.assign(new Agent(), {
                name: 'agent-essai',
                kind: KIND_REMOTE,
                credentialsMode,
                enabled,
                maxConcurrent: 1,
                createdAt: now()
            })
        );
    }

    const asAgent = (agent: Agent, secure = true) =>
        ({ agent, protocol: secure ? 'https' : 'http', headers: {} }) as unknown as AuthenticatedRequest;

    const noResponse = { status: () => undefined } as never;

    describe('annonce', () => {
        it('accepte un agent qui parle le bon contrat et retient ce qu’il déclare', async () => {
            const agent = await seedAgent();

            const identity = await controller.hello(
                { contract_version: CONTRACT_VERSION, hostname: 'runner-3', platform: 'linux/amd64', version: '0.2.0' },
                asAgent(agent)
            );

            expect(identity.contractVersion).toBe(CONTRACT_VERSION);
            const stored = await dataSource.manager.findOneByOrFail(Agent, { id: agent.id });
            expect(stored.hostname).toBe('runner-3');
            // `lastSeenAt` est ce qui distingue un agent en ligne d'un agent déclaré.
            expect(stored.lastSeenAt).not.toBeNull();
        });

        it('refuse un contrat incompatible en 409, pas en 400', async () => {
            const agent = await seedAgent();
            // La requête est bien formée ; les deux côtés sont en désaccord sur le
            // protocole, et le correctif est un déploiement.
            const failure = await controller.hello({ contract_version: '0' }, asAgent(agent)).catch((error) => error);
            expect(failure).toBeInstanceOf(ConflictException);
            expect(failure.message).toContain('Mettez l');
        });

        it('refuse un agent désactivé', async () => {
            const agent = await seedAgent(CREDENTIALS_LOCAL, false);
            await expect(controller.hello({ contract_version: CONTRACT_VERSION }, asAgent(agent))).rejects.toBeInstanceOf(UnauthorizedException);
        });

        it('refuse une requête sans agent authentifié', async () => {
            await expect(controller.hello({ contract_version: CONTRACT_VERSION }, {} as AuthenticatedRequest)).rejects.toBeInstanceOf(
                UnauthorizedException
            );
        });
    });

    describe('réclamation', () => {
        /** Une clé de déploiement chiffrée au repos, comme en base. */
        async function seedSshKey(): Promise<SshKey> {
            const id = '44444444-4444-4444-4444-444444444444';
            return dataSource.manager.save(
                SshKey,
                Object.assign(new SshKey(), {
                    id,
                    name: 'déploiement',
                    privateKey: encryptWith(deriveKey(KEY), PRIVATE, privateKeyContext(id)),
                    publicKey: null,
                    createdAt: now()
                })
            );
        }

        async function queueScan(sshKeyId: string | null = null): Promise<Scan> {
            const repository = await dataSource.manager.save(
                GitRepository,
                Object.assign(new GitRepository(), { url: 'git://127.0.0.1:9/x.git', branch: 'main', sshKeyId })
            );
            return dataSource.manager.save(
                Scan,
                Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: STATUS_QUEUED, createdAt: now() })
            );
        }

        it('rend 204 quand il n’y a rien à faire', async () => {
            const agent = await seedAgent();
            let status = 200;

            const task = await controller.claimJob(asAgent(agent), { status: (code: number) => (status = code) } as never, undefined, '0');

            expect(task).toBeUndefined();
            // 204 et non un objet vide : « y a-t-il du travail ? » se lit au statut.
            expect(status).toBe(204);
        });

        it('confie une tâche et marque le scan comme réclamé', async () => {
            const agent = await seedAgent();
            const scan = await queueScan();

            const task = await controller.claimJob(asAgent(agent), noResponse, undefined, '0');

            expect(task).toBeDefined();
            expect(task!.scanId).toBe(scan.id);
            const claimed = await dataSource.manager.findOneByOrFail(Scan, { id: scan.id });
            expect(claimed.claimedBy).toBe(agent.id);
            expect(claimed.leaseExpiresAt).not.toBeNull();
        });

        it('refuse de livrer une clé de déploiement en clair, et remet le scan en file', async () => {
            const agent = await seedAgent(CREDENTIALS_DELEGATED);
            const key = await dataSource.manager.save(
                SshKey,
                Object.assign(new SshKey(), {
                    id: '11111111-1111-1111-1111-111111111111',
                    name: 'déploiement',
                    privateKey: encryptWith(deriveKey(KEY), PRIVATE, privateKeyContext('11111111-1111-1111-1111-111111111111')),
                    publicKey: null,
                    createdAt: now()
                })
            );
            const scan = await queueScan(key.id);

            // Le contrôleur refuse avant même de réclamer, sur le mode de l'agent.
            await expect(controller.claimJob(asAgent(agent, false), noResponse, undefined, '0')).rejects.toBeInstanceOf(
                PreconditionFailedException
            );

            // Le scan doit rester réclamable : sinon il attendrait l'expiration d'un bail
            // que personne ne détient.
            const untouched = await dataSource.manager.findOneByOrFail(Scan, { id: scan.id });
            expect(untouched.status).toBe(STATUS_QUEUED);
        });

        it('livre la clé quand la liaison est chiffrée', async () => {
            const agent = await seedAgent(CREDENTIALS_DELEGATED);
            const key = await dataSource.manager.save(
                SshKey,
                Object.assign(new SshKey(), {
                    id: '22222222-2222-2222-2222-222222222222',
                    name: 'déploiement',
                    privateKey: encryptWith(deriveKey(KEY), PRIVATE, privateKeyContext('22222222-2222-2222-2222-222222222222')),
                    publicKey: null,
                    createdAt: now()
                })
            );
            await queueScan(key.id);

            const task = await controller.claimJob(asAgent(agent, true), noResponse, undefined, '0');

            expect(task!.privateKey).toContain('PRIVATE KEY');
        });

        it("ne livre aucune clé à un agent en mode local, même sur une liaison chiffrée", async () => {
            // **Le cas qui manquait, et le seul qui vérifie la promesse faite à l'opérateur.**
            // L'écran /agents annonce « Zanshin ne lui envoie aucune clé » pour ce mode ;
            // c'est ce qui justifie de déporter un agent sur une machine moins protégée.
            // Sans ce test, le mode n'était qu'un libellé : la livraison ne regardait que le
            // transport, donc un agent `local` recevait la clé déchiffrée de chaque dépôt
            // dont il réclamait un scan — et la file n'étant routée par aucun critère, il
            // pouvait toutes les moissonner.
            const agent = await seedAgent(CREDENTIALS_LOCAL);
            const key = await dataSource.manager.save(
                SshKey,
                Object.assign(new SshKey(), {
                    id: '33333333-3333-3333-3333-333333333333',
                    name: 'déploiement',
                    privateKey: encryptWith(deriveKey(KEY), PRIVATE, privateKeyContext('33333333-3333-3333-3333-333333333333')),
                    publicKey: null,
                    createdAt: now()
                })
            );
            const scan = await queueScan(key.id);

            const task = await controller.claimJob(asAgent(agent, true), noResponse, undefined, '0');

            expect(task!.privateKey).toBeNull();
            // Et le scan lui est bien confié : refuser la clé ne doit pas refuser le
            // travail — un agent `local` scanne avec ses propres accès git.
            expect(task!.scanId).toBe(scan.id);
        });

        it("scelle la clé de déploiement pour l'agent qui a annoncé la sienne", async () => {
            // **Ce que TLS ne donne pas.** La plupart des déploiements terminent TLS sur un
            // proxy inverse : la clé SSH y est en clair, dans un vidage mémoire, dans un
            // journal de débogage, et pour qui administre ce proxy. Scellée, elle ne
            // s'ouvre que dans le processus de l'agent.
            const keyPair = generateEphemeralKeyPair();
            const agent = await seedAgent(CREDENTIALS_DELEGATED);
            await controller.hello({ contract_version: CONTRACT_VERSION, sealing_public_key: keyPair.publicKey }, asAgent(agent));
            const key = await seedSshKey();
            await queueScan(key.id);

            // Rechargé : c'est la ligne en base que la réclamation consulte, pas l'objet
            // que ce test tient en main depuis avant l'annonce.
            const announced = await dataSource.manager.findOneByOrFail(Agent, { id: agent.id });
            const task = await controller.claimJob(asAgent(announced, true), noResponse, undefined, '0');

            expect(isSealed(task!.privateKey)).toBe(true);
            expect(task!.privateKey).not.toContain('PRIVATE KEY');
            expect(openEnvelope(keyPair, task!.privateKey!)).toBe(PRIVATE);
        });

        it('délègue une clé scellée même sur une liaison en clair', async () => {
            // L'exigence de HTTPS protège ce qui voyage en clair. Une enveloppe scellée ne
            // l'est pas : maintenir le refus interdirait du travail sans rien protéger.
            const keyPair = generateEphemeralKeyPair();
            const agent = await seedAgent(CREDENTIALS_DELEGATED);
            await controller.hello({ contract_version: CONTRACT_VERSION, sealing_public_key: keyPair.publicKey }, asAgent(agent));
            const key = await seedSshKey();
            await queueScan(key.id);

            const announced = await dataSource.manager.findOneByOrFail(Agent, { id: agent.id });
            const task = await controller.claimJob(asAgent(announced, false), noResponse, undefined, '0');

            expect(openEnvelope(keyPair, task!.privateKey!)).toBe(PRIVATE);
        });

        it('refuse une clé de scellement illisible plutôt que de la retenir', async () => {
            // Retenue, elle provoquerait une exception au milieu d'une réclamation. `null`
            // ferait retomber l'agent sur la clé en clair — silencieusement, ce qui est
            // pire : l'opérateur croirait sceller.
            const agent = await seedAgent(CREDENTIALS_DELEGATED);

            await expect(
                controller.hello({ contract_version: CONTRACT_VERSION, sealing_public_key: 'pas-une-cle' }, asAgent(agent))
            ).rejects.toBeInstanceOf(BadRequestException);
        });

        it("confie le scan à un agent local même en clair, puisqu'aucune clé ne part", async () => {
            // Corollaire du précédent : la vérification de transport ne concerne que la
            // livraison d'une clé. L'appliquer à un agent qui n'en reçoit aucune refuserait
            // du travail sans rien protéger — et le refus remontait en 500, pas en 412.
            const agent = await seedAgent(CREDENTIALS_LOCAL);
            const key = await dataSource.manager.save(
                SshKey,
                Object.assign(new SshKey(), {
                    id: '44444444-4444-4444-4444-444444444444',
                    name: 'déploiement',
                    privateKey: encryptWith(deriveKey(KEY), PRIVATE, privateKeyContext('44444444-4444-4444-4444-444444444444')),
                    publicKey: null,
                    createdAt: now()
                })
            );
            await queueScan(key.id);

            const task = await controller.claimJob(asAgent(agent, false), noResponse, undefined, '0');

            expect(task!.privateKey).toBeNull();
        });
    });

    describe('bail', () => {
        it('prolonge le bail du scan qu’il détient', async () => {
            const agent = await seedAgent();
            const repository = await dataSource.manager.save(
                GitRepository,
                Object.assign(new GitRepository(), { url: 'git://127.0.0.1:9/x.git', branch: 'main' })
            );
            await dataSource.manager.save(
                Scan,
                Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: STATUS_QUEUED, createdAt: now() })
            );
            const task = await controller.claimJob(asAgent(agent), noResponse, undefined, '0');

            await expect(controller.heartbeat(task!.scanId, asAgent(agent))).resolves.toBeUndefined();
        });

        it('refuse en 409 le signe de vie d’un agent qui a perdu son bail', async () => {
            const agent = await seedAgent();
            const other = await dataSource.manager.save(
                Agent,
                Object.assign(new Agent(), { name: 'autre', kind: KIND_REMOTE, credentialsMode: CREDENTIALS_LOCAL, enabled: true, createdAt: now() })
            );
            const repository = await dataSource.manager.save(
                GitRepository,
                Object.assign(new GitRepository(), { url: 'git://127.0.0.1:9/x.git', branch: 'main' })
            );
            await dataSource.manager.save(
                Scan,
                Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: STATUS_QUEUED, createdAt: now() })
            );
            const task = await controller.claimJob(asAgent(agent), noResponse, undefined, '0');

            // L'agent doit abandonner plutôt que de rendre un résultat qui écraserait
            // celui de son successeur.
            await expect(controller.heartbeat(task!.scanId, asAgent(other))).rejects.toBeInstanceOf(ConflictException);
        });
    });

    describe('résultat', () => {
        it('accepte les constats et clôt le scan', async () => {
            const agent = await seedAgent();
            const repository = await dataSource.manager.save(
                GitRepository,
                Object.assign(new GitRepository(), { url: 'git://127.0.0.1:9/x.git', branch: 'main' })
            );
            await dataSource.manager.save(
                Scan,
                Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: STATUS_QUEUED, createdAt: now() })
            );
            const task = await controller.claimJob(asAgent(agent), noResponse, undefined, '0');

            const acknowledgement = await controller.submitResult(
                task!.scanId,
                {
                    secrets: [{ rule: 'aws-key', description: 'Clé AWS', file: 'config.py', line: 3, fingerprint: null }],
                    duration_ms: 1234
                },
                asAgent(agent)
            );

            expect(acknowledgement).toEqual({ accepted: true });
            const finished = await dataSource.manager.findOneByOrFail(Scan, { id: task!.scanId });
            expect(finished.status).toBe('completed');
            expect(finished.newIssuesCount).toBe(1);
            // Les étapes absentes du corps restent `null` : l'agent n'a pas cherché de
            // dépendances, et le backlog de ce type doit rester intact.
            expect(finished.durationMs).toBe(1234);
        });

        it('écarte le résultat d’un agent qui a perdu son bail', async () => {
            const agent = await seedAgent();
            const other = await dataSource.manager.save(
                Agent,
                Object.assign(new Agent(), { name: 'autre', kind: KIND_REMOTE, credentialsMode: CREDENTIALS_LOCAL, enabled: true, createdAt: now() })
            );
            const repository = await dataSource.manager.save(
                GitRepository,
                Object.assign(new GitRepository(), { url: 'git://127.0.0.1:9/x.git', branch: 'main' })
            );
            await dataSource.manager.save(
                Scan,
                Object.assign(new Scan(), { repoId: repository.id, branch: 'main', status: STATUS_QUEUED, createdAt: now() })
            );
            const task = await controller.claimJob(asAgent(agent), noResponse, undefined, '0');

            await expect(controller.submitResult(task!.scanId, { secrets: [] }, asAgent(other))).rejects.toBeInstanceOf(ConflictException);
            // Rien n'a été écrit : le scan appartient toujours au premier.
            const scan = await dataSource.manager.findOneByOrFail(Scan, { id: task!.scanId });
            expect(scan.status).toBe('scanning');
        });
    });
});
