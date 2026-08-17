import { CONTRACT_VERSION } from '../domain/agents/contract';
import type { ScanArtifacts } from '../scanning/scan-runner';
import { generateEphemeralKeyPair, seal, type EphemeralKeyPair } from '../domain/crypto/sealed-envelope';
import { AgentProtocol, ContractMismatch, type HttpCall, Unauthorized } from './protocol';

const DESCRIPTION = { hostname: 'runner-1', platform: 'linux 6.1', version: '1', scannerEngine: 'docker' };

/** Un serveur simulé qui enregistre ce qu'on lui envoie. */
function server(responses: Record<string, { status: number; body?: unknown }>, keyPair: EphemeralKeyPair | null = null) {
    const calls: { path: string; method: string; body?: unknown }[] = [];
    const call: HttpCall = async (path, init) => {
        calls.push({ path, method: init.method, body: init.body });
        const key = Object.keys(responses).find((prefix) => path.startsWith(prefix));
        const response = key ? responses[key] : { status: 404, body: { message: 'route inconnue' } };
        return { status: response.status, body: response.body ?? null };
    };
    return { calls, protocol: new AgentProtocol(call, keyPair) };
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

        it('annonce sa clé publique éphémère, et null quand il n’en a pas', async () => {
            const keyPair = generateEphemeralKeyPair();
            const avec = server({ '/api/v1/agents/hello': { status: 200, body: {} } }, keyPair);
            await avec.protocol.hello(DESCRIPTION);
            expect((avec.calls[0].body as Record<string, unknown>).sealing_public_key).toBe(keyPair.publicKey);

            const sans = server({ '/api/v1/agents/hello': { status: 200, body: {} } });
            await sans.protocol.hello(DESCRIPTION);
            expect((sans.calls[0].body as Record<string, unknown>).sealing_public_key).toBeNull();
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

        it('ouvre une clé de déploiement scellée avant de rendre la tâche', async () => {
            // La boucle et le coureur n'ont pas à connaître le scellement : ce qui sort
            // d'ici est une clé utilisable, ou une erreur nommée.
            const keyPair = generateEphemeralKeyPair();
            const PRIVEE = '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n';
            const { protocol } = server(
                { '/api/v1/agents/jobs': { status: 200, body: { scanId: 7, url: 'git@exemple:x.git', branch: 'main', privateKey: seal(keyPair.publicKey, PRIVEE) } } },
                keyPair
            );

            expect((await protocol.claim(5))!.privateKey).toBe(PRIVEE);
        });

        it("échoue plutôt que de rendre une enveloppe qu'il ne sait pas ouvrir", async () => {
            // **Une enveloppe non ouverte ressemble à une clé.** Elle serait écrite dans un
            // fichier et passée à `git clone`, et l'échec ressemblerait à un problème de
            // dépôt ou de droits — l'opérateur chercherait du mauvais côté.
            const keyPair = generateEphemeralKeyPair();
            const scellee = seal(generateEphemeralKeyPair().publicKey, 'secret');
            const { protocol } = server(
                { '/api/v1/agents/jobs': { status: 200, body: { scanId: 7, url: 'git@exemple:x.git', branch: 'main', privateKey: scellee } } },
                keyPair
            );

            await expect(protocol.claim(5)).rejects.toThrow(/scellée/);
        });

        it("laisse passer une clé en clair, pour un plan de contrôle qui ne scelle pas", async () => {
            // Compatibilité descendante : le champ est optionnel des deux côtés, et un
            // agent à jour face à un plan de contrôle plus ancien doit continuer de scanner.
            const { protocol } = server(
                { '/api/v1/agents/jobs': { status: 200, body: { scanId: 7, url: 'x', branch: 'main', privateKey: 'CLÉ EN CLAIR' } } },
                generateEphemeralKeyPair()
            );

            expect((await protocol.claim(5))!.privateKey).toBe('CLÉ EN CLAIR');
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

describe('rule set fetching', () => {
    function protocolWith(responses: { status: number; body: unknown }[]) {
        const calls: string[] = [];
        let index = 0;
        const client = new AgentProtocol(async (path) => {
            calls.push(path);
            return responses[Math.min(index++, responses.length - 1)];
        }, null);
        return { client, calls };
    }

    it('fetches by hash and caches, so a second scan costs nothing', async () => {
        // **The cache needs no invalidation**, and that is the only reason to fetch by hash
        // rather than "the active set": a hash names a content, never a state.
        const files = [{ path: 'rule-0001.yaml', content: 'rules: []\n' }];
        const { client, calls } = protocolWith([{ status: 200, body: { contentHash: 'abc', files } }]);

        expect(await client.ruleSet('abc')).toEqual(files);
        expect(await client.ruleSet('abc')).toEqual(files);
        expect(calls).toEqual(['/api/v1/agents/rules/abc']);
    });

    it('asks again for a different hash', async () => {
        const { client, calls } = protocolWith([{ status: 200, body: { files: [] } }]);

        await client.ruleSet('abc');
        await client.ruleSet('def');
        expect(calls).toEqual(['/api/v1/agents/rules/abc', '/api/v1/agents/rules/def']);
    });

    it('throws rather than falling back to fewer rules', async () => {
        // The caller places this inside the SAST step, whose failure leaves the artifact at
        // `null`. Returning an empty list instead would let Semgrep run with the bundled
        // rule and report a shorter list — which reads as "analyzed, those issues are gone"
        // and resolves everything the operator's rules had found.
        const { client } = protocolWith([{ status: 404, body: null }]);

        await expect(client.ruleSet('missing')).rejects.toThrow(/HTTP 404/);
    });

    it('does not cache a failure', async () => {
        const { client, calls } = protocolWith([
            { status: 503, body: null },
            { status: 200, body: { files: [{ path: 'rule-0001.yaml', content: 'rules: []\n' }] } }
        ]);

        await expect(client.ruleSet('abc')).rejects.toThrow();
        expect((await client.ruleSet('abc')).length).toBe(1);
        expect(calls).toHaveLength(2);
    });
});
