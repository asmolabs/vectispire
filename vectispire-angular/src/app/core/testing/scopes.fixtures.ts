import { asSchema } from './contract';

/**
 * A project and its aggregates as the control plane answers them, checked against the published
 * contract. `Payments / Gateway` is seen in part — one repository of two — so every figure is
 * flagged `partial`, and its image has never been scanned, so the component list is incomplete.
 */
export const PROJECT_ID = 11;

export const OPEN_ISSUES = asSchema('OpenIssues', {
    critical: 2,
    high: 1,
    medium: 0,
    low: 0,
    negligible: 0,
    unknown: 0,
    total: 3
});

export const PROJECT_DETAIL = asSchema('ProjectDetail', {
    id: PROJECT_ID,
    solutionId: 1,
    name: 'Gateway',
    description: 'The public API edge',
    createdAt: '2026-09-01T00:00:00Z',
    partial: true,
    checklistsVisible: false,
    repositoryCount: 1,
    containerCount: 1,
    openIssues: OPEN_ISSUES,
    repositories: [{ id: 9, name: 'api-gateway' }],
    containers: [{ id: 4, name: 'ghcr.io/acme/gateway:2.1' }],
    detectedLanguages: ['java' as const, 'typescript' as const],
    languagesUnknownFor: [],
    solution: { id: 1, name: 'Payments' }
});

const controls = (status: 'COMPLIANT' | 'NO_DATA', score: number) => [
    {
        control: {
            id: 'NIS2-ART21-VULN',
            name: 'Vulnerability Handling',
            requirement: 'All known vulnerabilities must be tracked.',
            category: 'VULNERABILITY_MANAGEMENT'
        },
        status,
        scorePercentage: score,
        details: 'Two critical CVEs open.',
        remediationGuidance: 'Maintain continuous scanning.'
    }
];

/** Measured: one framework partial, one compliant, and a matrix row per visible target. */
export const COMPLIANCE_SUMMARY = asSchema('ComplianceSummary', {
    evaluations: [
        {
            framework: 'NIS_2' as const,
            scorePercentage: 72,
            overallStatus: 'PARTIAL' as const,
            controls: controls('COMPLIANT', 100)
        },
        { framework: 'DORA' as const, scorePercentage: 90, overallStatus: 'COMPLIANT' as const, controls: [] }
    ],
    mttr: { mttrBySeverityDays: { critical: 5.0 }, overallMttrDays: 5.0, resolvedCount: 3 },
    overdueCount: 1,
    dueSoonCount: 0,
    totalMonitoredTargets: 2,
    passingGateTargets: 1,
    observedTargets: 1,
    freshTargets: 1,
    targets: [
        {
            targetId: 'REPOSITORY:9',
            name: 'api-gateway',
            type: 'REPOSITORY' as const,
            gateStatus: 'FAILED' as const,
            openIssuesCount: 3,
            overdueCount: 1,
            overallStatus: 'PARTIAL' as const,
            overallScore: 72,
            frameworkScores: { NIS_2: 72, ISO_27001: 80, EU_CRA: 65 }
        }
    ]
});

/** Nothing of the scope was ever scanned: every verdict is NO_DATA, and its zero is no score. */
export const NO_DATA_SUMMARY = asSchema('ComplianceSummary', {
    evaluations: [
        {
            framework: 'NIS_2' as const,
            scorePercentage: 0,
            overallStatus: 'NO_DATA' as const,
            controls: controls('NO_DATA', 0)
        }
    ],
    mttr: { mttrBySeverityDays: {}, overallMttrDays: null, resolvedCount: 0 },
    overdueCount: 0,
    dueSoonCount: 0,
    totalMonitoredTargets: 1,
    passingGateTargets: 0,
    observedTargets: 0,
    freshTargets: 0,
    targets: []
});

export const SCORECARD = asSchema('SecurityScorecard', {
    targetId: PROJECT_ID,
    targetKind: 'project',
    targetName: 'Gateway',
    score: 64,
    grade: 'C' as const,
    openKevCount: 1,
    openCriticalCount: 2,
    openHighCount: 1,
    licenseViolationCount: 0,
    overdueCount: 1,
    hasAttestation: true,
    recommendations: ['Fix the actively exploited vulnerability first.']
});

export const PROJECT_COMPLIANCE = asSchema('ScopeCompliance', {
    kind: 'project',
    id: PROJECT_ID,
    name: 'Gateway',
    partial: true,
    targetCount: 2,
    compliance: COMPLIANCE_SUMMARY,
    scorecard: SCORECARD
});

export const SOLUTION_COMPLIANCE_NO_DATA = asSchema('ScopeCompliance', {
    kind: 'solution',
    id: 2,
    name: 'Mobile',
    partial: false,
    targetCount: 1,
    compliance: NO_DATA_SUMMARY,
    scorecard: {
        ...SCORECARD,
        targetId: 2,
        targetKind: 'solution',
        targetName: 'Mobile',
        score: 90,
        grade: 'A' as const
    }
});

export const PROJECT_COMPONENTS = asSchema('ConsolidatedInventory', {
    kind: 'project',
    id: PROJECT_ID,
    name: 'Gateway',
    partial: true,
    complete: false,
    targets: [
        {
            kind: 'repository',
            id: 9,
            name: 'api-gateway',
            scanId: 501,
            scannedAt: '2026-09-29T08:00:00Z',
            inventory: 'listed' as const,
            componentCount: 2
        },
        {
            kind: 'container',
            id: 4,
            name: 'ghcr.io/acme/gateway:2.1',
            scanId: null,
            scannedAt: null,
            inventory: 'never_scanned' as const,
            componentCount: 0
        }
    ],
    components: [
        {
            name: 'jackson-databind',
            version: '2.17.1',
            purl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.1',
            type: 'library',
            targets: [{ kind: 'repository', id: 9, name: 'api-gateway' }]
        },
        {
            name: 'lodash',
            version: '4.17.21',
            purl: 'pkg:npm/lodash@4.17.21',
            type: 'library',
            targets: [{ kind: 'repository', id: 9, name: 'api-gateway' }]
        }
    ]
});

export const COMPLETE_COMPONENTS = asSchema('ConsolidatedInventory', {
    ...PROJECT_COMPONENTS,
    partial: false,
    complete: true,
    targets: [PROJECT_COMPONENTS.targets[0]]
});
