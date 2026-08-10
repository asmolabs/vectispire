import { BUILT_IN_POLICY, GateIssue, evaluate } from './policy-gate';
import { SOURCE_BUILT_IN, SOURCE_GLOBAL, SOURCE_TARGET, StoredPolicy } from './policy-resolution';
import {
    OBSERVATION_LAST_SCAN_FAILED,
    OBSERVATION_NEVER_SCANNED,
    OBSERVATION_OK,
    OverviewInput,
    TARGET_CONTAINER,
    TARGET_REPOSITORY,
    buildOverview
} from './security-overview';

const issue = (over: Partial<GateIssue & { repoId: number | null; containerId: number | null }> = {}) => ({
    id: 1,
    state: 'open',
    type: 'vulnerability',
    severity: 'critical',
    identifier: 'CVE-2024-1234',
    packageName: 'requests',
    fixVersions: '2.32.0',
    isKev: false,
    triageStatus: 'under_review',
    repoId: 1,
    containerId: null,
    ...over
});

const input = (over: Partial<OverviewInput> = {}): OverviewInput => ({
    repositories: [{ id: 1, name: 'org/projet' }],
    containers: [],
    policies: [],
    openIssues: [],
    latestScanByRepository: new Map([[1, { id: 10, status: 'completed', createdAt: '2026-08-10T08:00:00' }]]),
    latestScanByContainer: new Map(),
    ...over
});

describe('vue de posture', () => {
    it('rend un verdict par cible', () => {
        const overview = buildOverview(input({ openIssues: [issue()] }));

        expect(overview.totalCount).toBe(1);
        expect(overview.failingCount).toBe(1);
        expect(overview.targets[0].passed).toBe(false);
    });

    it('mêle dépôts et conteneurs', () => {
        const overview = buildOverview(
            input({
                containers: [{ id: 5, name: 'nginx:1.25' }],
                latestScanByContainer: new Map([[5, { id: 20, status: 'completed', createdAt: '2026-08-09T08:00:00' }]])
            })
        );

        expect(overview.targets.map((target) => target.kind)).toEqual([TARGET_REPOSITORY, TARGET_CONTAINER]);
    });

    it("n'attribue pas les problèmes d'un dépôt à un conteneur du même identifiant", () => {
        // `repoId` et `containerId` sont exclusifs : les confondre ferait échouer une
        // cible pour les problèmes d'une autre.
        const overview = buildOverview(
            input({
                containers: [{ id: 1, name: 'nginx:1.25' }],
                latestScanByContainer: new Map([[1, { id: 20, status: 'completed', createdAt: '2026-08-09T08:00:00' }]]),
                openIssues: [issue({ repoId: 1, containerId: null })]
            })
        );

        const [repository, container] = overview.targets;
        expect(repository.passed).toBe(false);
        expect(container.passed).toBe(true);
    });

    describe('le verdict est celui de l’API, pas un second qui lui ressemble', () => {
        it('coïncide avec un appel direct à evaluate', () => {
            // C'est la propriété qui rend l'écran digne de confiance : une agrégation SQL
            // qui recompterait « les problèmes au-dessus du seuil » serait d'accord
            // aujourd'hui et divergerait au premier drapeau ajouté.
            const issues = [issue({ id: 1, severity: 'high' }), issue({ id: 2, severity: 'medium', isKev: true }), issue({ id: 3, type: 'quality', severity: 'critical' })];

            const overview = buildOverview(input({ openIssues: issues }));

            expect(overview.targets[0].verdict).toEqual(evaluate(issues, BUILT_IN_POLICY));
        });
    });

    describe('résolution de politique, en mémoire', () => {
        const targetPolicy: StoredPolicy = { ...BUILT_IN_POLICY, failOnSeverity: 'low', version: 7 };
        const globalPolicy: StoredPolicy = { ...BUILT_IN_POLICY, failOnSeverity: 'medium', version: 3 };

        it('applique la politique de la cible quand elle existe', () => {
            const overview = buildOverview(input({ policies: [{ targetKind: TARGET_REPOSITORY, targetId: 1, policy: targetPolicy }] }));
            expect(overview.targets[0].policy.source).toBe(SOURCE_TARGET);
            expect(overview.targets[0].policy.version).toBe(7);
        });

        it('retombe sur la globale', () => {
            const overview = buildOverview(input({ policies: [{ targetKind: 'global', targetId: 0, policy: globalPolicy }] }));
            expect(overview.targets[0].policy.source).toBe(SOURCE_GLOBAL);
        });

        it('retombe sur l’intégrée', () => {
            expect(buildOverview(input()).targets[0].policy.source).toBe(SOURCE_BUILT_IN);
        });

        it('n’applique pas la politique d’une cible à une autre', () => {
            const overview = buildOverview(
                input({
                    repositories: [
                        { id: 1, name: 'a' },
                        { id: 2, name: 'b' }
                    ],
                    latestScanByRepository: new Map([
                        [1, { id: 10, status: 'completed', createdAt: '2026-08-10T08:00:00' }],
                        [2, { id: 11, status: 'completed', createdAt: '2026-08-10T08:00:00' }]
                    ]),
                    policies: [{ targetKind: TARGET_REPOSITORY, targetId: 1, policy: targetPolicy }]
                })
            );

            expect(overview.targets[0].policy.source).toBe(SOURCE_TARGET);
            expect(overview.targets[1].policy.source).toBe(SOURCE_BUILT_IN);
        });
    });

    describe('une cible non observée n’est pas une cible qui passe', () => {
        it('signale une cible jamais scannée', () => {
            // Un backlog vide passe toutes les politiques. Le dire sans ce qualificatif
            // serait la chose la plus trompeuse que cet écran puisse faire.
            const overview = buildOverview(input({ latestScanByRepository: new Map() }));

            expect(overview.targets[0].passed).toBe(true);
            expect(overview.targets[0].observed).toBe(false);
            expect(overview.targets[0].observation).toBe(OBSERVATION_NEVER_SCANNED);
            expect(overview.neverScannedCount).toBe(1);
        });

        it('signale un dernier scan en échec', () => {
            const overview = buildOverview(input({ latestScanByRepository: new Map([[1, { id: 10, status: 'failed', createdAt: '2026-08-10T08:00:00' }]]) }));

            expect(overview.targets[0].observed).toBe(false);
            expect(overview.targets[0].observation).toBe(OBSERVATION_LAST_SCAN_FAILED);
            expect(overview.lastScanFailedCount).toBe(1);
        });

        it('considère observée une cible dont le dernier scan a réussi', () => {
            const overview = buildOverview(input());
            expect(overview.targets[0].observation).toBe(OBSERVATION_OK);
            expect(overview.targets[0].observed).toBe(true);
        });

        it('ne compte pas un scan en cours comme un échec', () => {
            const overview = buildOverview(input({ latestScanByRepository: new Map([[1, { id: 10, status: 'scanning', createdAt: '2026-08-10T08:00:00' }]]) }));
            expect(overview.lastScanFailedCount).toBe(0);
            expect(overview.neverScannedCount).toBe(0);
            expect(overview.targets[0].observed).toBe(false);
        });
    });

    describe('compteur de KEV', () => {
        it('compte les KEV qui pèsent réellement sur un verdict', () => {
            const overview = buildOverview(input({ openIssues: [issue({ id: 1, isKev: true }), issue({ id: 2, isKev: true }), issue({ id: 3 })] }));
            expect(overview.kevCount).toBe(2);
        });

        it('ne compte pas un KEV écarté par un triage', () => {
            // Il ne pèse pas sur le verdict ; l'afficher dans le même bandeau ferait lire
            // un chiffre qui ne correspond à rien de ce que la page montre.
            const overview = buildOverview(input({ openIssues: [issue({ isKev: true, triageStatus: 'not_affected' })] }));
            expect(overview.kevCount).toBe(0);
        });
    });

    it('reste cohérente sur un inventaire vide', () => {
        const overview = buildOverview(input({ repositories: [], latestScanByRepository: new Map() }));
        expect(overview).toMatchObject({ totalCount: 0, failingCount: 0, kevCount: 0, neverScannedCount: 0, lastScanFailedCount: 0 });
    });
});
