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
    latestScanByRepository: new Map([[1, { id: 10, status: 'completed', createdAt: new Date('2026-08-10T08:00:00Z') }]]),
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

    it('mixes repositories and containers', () => {
        const overview = buildOverview(
            input({
                containers: [{ id: 5, name: 'nginx:1.25' }],
                latestScanByContainer: new Map([[5, { id: 20, status: 'completed', createdAt: new Date('2026-08-09T08:00:00Z') }]])
            })
        );

        expect(overview.targets.map((target) => target.kind)).toEqual([TARGET_REPOSITORY, TARGET_CONTAINER]);
    });

    it("does not attribute a repository's issues to a container of the same id", () => {
        // `repoId` and `containerId` are mutually exclusive: confusing them would fail one
        // target for another's issues.
        const overview = buildOverview(
            input({
                containers: [{ id: 1, name: 'nginx:1.25' }],
                latestScanByContainer: new Map([[1, { id: 20, status: 'completed', createdAt: new Date('2026-08-09T08:00:00Z') }]]),
                openIssues: [issue({ repoId: 1, containerId: null })]
            })
        );

        const [repository, container] = overview.targets;
        expect(repository.passed).toBe(false);
        expect(container.passed).toBe(true);
    });

    describe('le verdict est celui de l’API, pas un second qui lui ressemble', () => {
        it('agrees with a direct call to evaluate', () => {
            // This is the property that makes the screen trustworthy: a SQL aggregate
            // recounting "issues above the threshold" would agree today and diverge the
            // first time a flag was added.
            const issues = [issue({ id: 1, severity: 'high' }), issue({ id: 2, severity: 'medium', isKev: true }), issue({ id: 3, type: 'quality', severity: 'critical' })];

            const overview = buildOverview(input({ openIssues: issues }));

            expect(overview.targets[0].verdict).toEqual(evaluate(issues, BUILT_IN_POLICY));
        });
    });

    describe('policy resolution, in memory', () => {
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

        it('falls back to the built-in one', () => {
            expect(buildOverview(input()).targets[0].policy.source).toBe(SOURCE_BUILT_IN);
        });

        it("does not apply one target's policy to another", () => {
            const overview = buildOverview(
                input({
                    repositories: [
                        { id: 1, name: 'a' },
                        { id: 2, name: 'b' }
                    ],
                    latestScanByRepository: new Map([
                        [1, { id: 10, status: 'completed', createdAt: new Date('2026-08-10T08:00:00Z') }],
                        [2, { id: 11, status: 'completed', createdAt: new Date('2026-08-10T08:00:00Z') }]
                    ]),
                    policies: [{ targetKind: TARGET_REPOSITORY, targetId: 1, policy: targetPolicy }]
                })
            );

            expect(overview.targets[0].policy.source).toBe(SOURCE_TARGET);
            expect(overview.targets[1].policy.source).toBe(SOURCE_BUILT_IN);
        });
    });

    describe('an unobserved target is not a target that passes', () => {
        it('flags a target never scanned', () => {
            // Un backlog vide passe toutes les politiques. Le dire sans ce qualificatif
            // would be the most misleading thing this screen could do.
            const overview = buildOverview(input({ latestScanByRepository: new Map() }));

            expect(overview.targets[0].passed).toBe(true);
            expect(overview.targets[0].observed).toBe(false);
            expect(overview.targets[0].observation).toBe(OBSERVATION_NEVER_SCANNED);
            expect(overview.neverScannedCount).toBe(1);
        });

        it('flags a last scan that failed', () => {
            const overview = buildOverview(input({ latestScanByRepository: new Map([[1, { id: 10, status: 'failed', createdAt: new Date('2026-08-10T08:00:00Z') }]]) }));

            expect(overview.targets[0].observed).toBe(false);
            expect(overview.targets[0].observation).toBe(OBSERVATION_LAST_SCAN_FAILED);
            expect(overview.lastScanFailedCount).toBe(1);
        });

        it('treats a target whose last scan succeeded as observed', () => {
            const overview = buildOverview(input());
            expect(overview.targets[0].observation).toBe(OBSERVATION_OK);
            expect(overview.targets[0].observed).toBe(true);
        });

        it('does not count a scan in progress as a failure', () => {
            const overview = buildOverview(input({ latestScanByRepository: new Map([[1, { id: 10, status: 'scanning', createdAt: new Date('2026-08-10T08:00:00Z') }]]) }));
            expect(overview.lastScanFailedCount).toBe(0);
            expect(overview.neverScannedCount).toBe(0);
            expect(overview.targets[0].observed).toBe(false);
        });
    });

    describe('compteur de KEV', () => {
        it('counts the KEVs that actually weigh on a verdict', () => {
            const overview = buildOverview(input({ openIssues: [issue({ id: 1, isKev: true }), issue({ id: 2, isKev: true }), issue({ id: 3 })] }));
            expect(overview.kevCount).toBe(2);
        });

        it('does not count a KEV discarded by a triage', () => {
            // It does not weigh on the verdict; showing it in the same banner would present
            // a number matching nothing the page displays.
            const overview = buildOverview(input({ openIssues: [issue({ isKev: true, triageStatus: 'not_affected' })] }));
            expect(overview.kevCount).toBe(0);
        });
    });

    it('stays coherent on an empty inventory', () => {
        const overview = buildOverview(input({ repositories: [], latestScanByRepository: new Map() }));
        expect(overview).toMatchObject({ totalCount: 0, failingCount: 0, kevCount: 0, neverScannedCount: 0, lastScanFailedCount: 0 });
    });
});
