import { CONTRACT_VERSION } from '../domain/agents/contract';
import type { ScanArtifacts } from '../scanning/scan-runner';
import { AgentProtocol, ContractMismatch, type HttpCall, Unauthorized } from './protocol';

const DESCRIPTION = { hostname: 'runner-1', platform: 'linux 6.1', version: '1', scannerEngine: 'docker' };

/** Un serveur simulé qui enregistre ce qu'on lui envoie. */
function server(responses: Record<string, { status: number; body?: unknown }>) {
    const calls: { path: string; method: string; body?: unknown }[] = [];
    const call: HttpCall = async (path, init) => {
        calls.push({ path, method: init.method, body: init.body });
        const key = Object.keys(responses).find((prefix) => path.startsWith(prefix));
        const response = key ? responses[key] : { status: 404, body: { message: 'route inconnue' } };
        return { status: response.status, body: response.body ?? null };
    };
    return { calls, protocol: new AgentProtocol(call) };
}

describe('protocole de l’agent', () => {
    describe('hello', () => {
        it("annonce sa version de contrat et rend l'identité", async () => {
            const { calls, protocol } = server({
                '/api/v1/agents/hello': { status: 201, body: { id: 'a1', name: 'runner-1', contractVersion: '1', maxConcurrent: 1, credentialsMode: 'local' } }
            });

            const identity = await protocol.hello(DESCRIPTION);

            expect(identity.name).toBe('runner-1');
            expect((calls[0].body as { contract_version: string }).contract_version).toBe(CONTRACT_VERSION);
        });

        it("distingue un désaccord de contrat d'une clé refusée", async () => {
            // Les deux correctifs diffèrent : l'un est un déploiement, l'autre une
            // configuration. Les confondre enverrait l'opérateur au mauvais endroit.
            const mismatch = server({ '/api/v1/agents/hello': { status: 409, body: { message: 'Mettez l’agent à jour.' } } });
            await expect(mismatch.protocol.hello(DESCRIPTION)).rejects.toBeInstanceOf(ContractMismatch);

            const refused = server({ '/api/v1/agents/hello': { status: 401, body: { message: 'Clé absente.' } } });
            await expect(refused.protocol.hello(DESCRIPTION)).rejects.toBeInstanceOf(Unauthorized);
        });

        it("relaie le message du serveur, qui porte la raison", async () => {
            const { protocol } = server({ '/api/v1/agents/hello': { status: 409, body: { message: 'contrat « 0 » contre « 1 »' } } });

            await expect(protocol.hello(DESCRIPTION)).rejects.toThrow(/contrat « 0 »/);
        });
    });

    describe('claim', () => {
        it('rend null sur 204 plutôt que de deviner', async () => {
            // La question « y a-t-il du travail ? » se lit au code de statut, sans analyser
            // un corps.
            const { protocol } = server({ '/api/v1/agents/jobs': { status: 204 } });

            expect(await protocol.claim(5)).toBeNull();
        });

        it('rend la tâche et demande une attente longue', async () => {
            const { calls, protocol } = server({
                '/api/v1/agents/jobs': { status: 200, body: { scanId: 7, url: 'git@exemple:x.git', branch: 'main' } }
            });

            const task = await protocol.claim(30);

            expect(task?.scanId).toBe(7);
            expect(calls[0].path).toContain('wait=30');
        });

        it('nomme le refus dû à une liaison non chiffrée', async () => {
            // Sans ce message, scanner sans la clé produirait un échec de clone qui
            // ressemble à un problème de réseau, et l'opérateur chercherait au pare-feu.
            const { protocol } = server({
                '/api/v1/agents/jobs': { status: 412, body: { message: "La requête n'est pas arrivée en HTTPS." } }
            });

            await expect(protocol.claim(5)).rejects.toThrow(/HTTPS/);
        });
    });

    describe('heartbeat', () => {
        it('rend false sur 409, qui veut dire « le bail est à un autre »', async () => {
            const { protocol } = server({ '/api/v1/agents/jobs/7/heartbeat': { status: 409 } });

            expect(await protocol.heartbeat(7)).toBe(false);
        });

        it('rend true quand le bail tient', async () => {
            const { protocol } = server({ '/api/v1/agents/jobs/7/heartbeat': { status: 204 } });

            expect(await protocol.heartbeat(7)).toBe(true);
        });
    });

    describe('submit', () => {
        const artifacts: ScanArtifacts = {
            sbom: null,
            dependencies: [],
            secrets: null,
            iac: null,
            sast: null,
            failures: [{ step: 'iac', reason: 'image absente' }],
            durationMs: 4242
        };

        it('envoie les champs sous le nom que le plan de contrôle lit', async () => {
            // `duration_ms` et non `durationMs` : l'écart est exactement le genre de détail
            // qui se perd sans être signalé — le serveur lirait `undefined` et enregistrerait
            // une durée de zéro.
            const { calls, protocol } = server({ '/api/v1/agents/jobs/7/result': { status: 201, body: { accepted: true } } });

            expect(await protocol.submit(7, artifacts)).toBe(true);

            const body = calls[0].body as Record<string, unknown>;
            expect(body.duration_ms).toBe(4242);
            expect(body).not.toHaveProperty('durationMs');
        });

        it('préserve `null` contre `[]`, qui décide du sort du backlog', async () => {
            // « L'étape n'a pas tourné » et « l'étape n'a rien trouvé » ne doivent pas se
            // confondre : transformer l'un en l'autre résoudrait tout un type en silence.
            const { calls, protocol } = server({ '/api/v1/agents/jobs/7/result': { status: 201 } });

            await protocol.submit(7, artifacts);

            const body = calls[0].body as Record<string, unknown>;
            expect(body.dependencies).toEqual([]);
            expect(body.secrets).toBeNull();
            expect(body.sast).toBeNull();
        });

        it('rend false sur 409, sans lever', async () => {
            const { protocol } = server({ '/api/v1/agents/jobs/7/result': { status: 409 } });

            expect(await protocol.submit(7, artifacts)).toBe(false);
        });
    });
});
