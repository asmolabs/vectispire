import type { ScanArtifacts } from '../scanning/scan-runner';
import { type LoopOptions, runOnce } from './agent-loop';
import type { AgentProtocol, AssignedTask } from './protocol';

const TASK: AssignedTask = { scanId: 7, url: 'git@exemple:org/projet.git', branch: 'main' };

const ARTIFACTS: ScanArtifacts = {
    sbom: { artifacts: [] } as unknown as ScanArtifacts['sbom'],
    dependencies: [],
    secrets: null,
    iac: null,
    sast: null,
    failures: [],
    durationMs: 1234
};

/** Un protocole simulé, dont chaque route est pilotée par le test. */
function protocol(over: Partial<Record<'claim' | 'heartbeat' | 'submit', unknown>> = {}) {
    const submitted: { scanId: number; artifacts: ScanArtifacts }[] = [];
    const service = {
        claim: over.claim ?? (async () => TASK),
        heartbeat: over.heartbeat ?? (async () => true),
        submit:
            over.submit ??
            (async (scanId: number, artifacts: ScanArtifacts) => {
                submitted.push({ scanId, artifacts });
                return true;
            })
    } as unknown as AgentProtocol;
    return { service, submitted };
}

function options(over: Partial<LoopOptions> = {}): LoopOptions {
    return {
        waitSeconds: 1,
        retryDelayMs: 1,
        // Très long : les cas qui ne portent pas sur le battement ne doivent pas en
        // déclencher un et devenir sensibles à la durée réelle du test.
        heartbeatMs: 1_000_000,
        sleep: async () => {},
        log: () => {},
        warn: () => {},
        ...over
    };
}

describe("boucle de l'agent", () => {
    it('exécute la tâche réclamée et rend son résultat', async () => {
        const { service, submitted } = protocol();

        const result = await runOnce(service, async () => ARTIFACTS, options());

        expect(result).toEqual({ completed: 1, failed: 0, abandoned: 0 });
        expect(submitted).toEqual([{ scanId: 7, artifacts: ARTIFACTS }]);
    });

    it('ne fait rien quand la file est vide', async () => {
        const { service, submitted } = protocol({ claim: async () => null });
        const executed: unknown[] = [];

        const result = await runOnce(service, async (task) => {
            executed.push(task);
            return ARTIFACTS;
        }, options());

        expect(result).toEqual({ completed: 0, failed: 0, abandoned: 0 });
        expect(executed).toEqual([]);
        expect(submitted).toEqual([]);
    });

    it("ne rend **rien** quand l'exécution échoue", async () => {
        // Le cas le plus important du fichier. Un agent qui posterait un résultat vide
        // après un échec ferait résoudre en silence tout le backlog des types qu'il n'a pas
        // regardés — `null` contre `[]`, la distinction que tout ce système protège.
        const { service, submitted } = protocol();

        const result = await runOnce(
            service,
            async () => {
                throw new Error('clone refusé');
            },
            options()
        );

        expect(result).toEqual({ completed: 0, failed: 1, abandoned: 0 });
        expect(submitted).toEqual([]);
    });

    it('écarte son résultat quand le bail a été repris pendant le travail', async () => {
        // Rendre écraserait celui du successeur, qui est plus récent.
        const { service, submitted } = protocol({ heartbeat: async () => false });

        const result = await runOnce(service, async () => {
            // Laisse un battement se produire avant la fin de l'exécution.
            await new Promise((resolve) => setTimeout(resolve, 30));
            return ARTIFACTS;
        }, options({ heartbeatMs: 5 }));

        expect(result).toEqual({ completed: 0, failed: 0, abandoned: 1 });
        expect(submitted).toEqual([]);
    });

    it("n'abandonne pas un scan valide sur un battement manqué", async () => {
        // Le réseau hoquette et le bail dure plusieurs fois l'intervalle : traiter une
        // erreur de battement comme une perte de bail jetterait du travail bon.
        const warnings: string[] = [];
        const { service, submitted } = protocol({
            heartbeat: async () => {
                throw new Error('ECONNRESET');
            }
        });

        const result = await runOnce(service, async () => {
            await new Promise((resolve) => setTimeout(resolve, 30));
            return ARTIFACTS;
        }, options({ heartbeatMs: 5, warn: (m) => warnings.push(m) }));

        expect(result).toEqual({ completed: 1, failed: 0, abandoned: 0 });
        expect(submitted).toHaveLength(1);
        expect(warnings.some((message) => message.includes('Signe de vie manqué'))).toBe(true);
    });

    it('arrête de battre une fois le scan terminé', async () => {
        // Un intervalle laissé courant retiendrait le processus et continuerait à
        // prolonger le bail d'un scan déjà rendu.
        let beats = 0;
        const { service } = protocol({
            heartbeat: async () => {
                beats += 1;
                return true;
            }
        });

        await runOnce(service, async () => {
            await new Promise((resolve) => setTimeout(resolve, 20));
            return ARTIFACTS;
        }, options({ heartbeatMs: 5 }));

        const afterRun = beats;
        await new Promise((resolve) => setTimeout(resolve, 30));
        expect(beats).toBe(afterRun);
    });

    it('compte comme abandonné un résultat que le serveur écarte', async () => {
        const { service } = protocol({ submit: async () => false });

        expect(await runOnce(service, async () => ARTIFACTS, options())).toEqual({ completed: 0, failed: 0, abandoned: 1 });
    });

    it('attend avant de réessayer quand la réclamation échoue', async () => {
        // Une panne de réclamation n'est pas un scan perdu, mais boucler sans pause
        // martèlerait un plan de contrôle déjà en difficulté.
        const slept: number[] = [];
        const { service } = protocol({
            claim: async () => {
                throw new Error('503');
            }
        });

        const result = await runOnce(service, async () => ARTIFACTS, options({ retryDelayMs: 42, sleep: async (ms) => void slept.push(ms) }));

        expect(result).toEqual({ completed: 0, failed: 0, abandoned: 0 });
        expect(slept).toEqual([42]);
    });

    it("compte comme échoué un résultat qui n'a pas pu être transmis", async () => {
        const { service } = protocol({
            submit: async () => {
                throw new Error('502');
            }
        });

        expect(await runOnce(service, async () => ARTIFACTS, options())).toEqual({ completed: 0, failed: 1, abandoned: 0 });
    });
});
