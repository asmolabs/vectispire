import type {
    ForgeCandidate,
    ForgeCandidatePage,
    ForgeConnection,
    ForgeDiscovery,
    ForgeImportPreview,
    ForgeImportResult,
    ForgeRepository
} from '../api.models';
import { asSchema } from './contract';

/**
 * A self-managed GitLab on an internal network behind its own CA — the estate decision 0037 was written
 * for — its discoveries, a selection table and an import, each read against the published schema.
 */
export const CONNECTION_ID = '6f1c2a9e-0b7d-4c3e-9a51-3d2e8f40b7aa';

export const COMPLETED_DISCOVERY: ForgeDiscovery = asSchema('ForgeDiscoveryView', {
    id: 12,
    connectionId: CONNECTION_ID,
    state: 'completed',
    reason: null,
    detail: null,
    attempts: 1,
    namespacesSeen: 4,
    repositoriesSeen: 37,
    repositoriesSkipped: 0,
    requestsMade: 41,
    rateLimitWaitSeconds: 0,
    rateLimitResetAt: null,
    requestedAt: '2026-10-03T08:00:00Z',
    requestedBy: 'admin',
    startedAt: '2026-10-03T08:00:02Z',
    finishedAt: '2026-10-03T08:01:10Z',
    newCount: 3,
    changedCount: 1,
    goneCount: 2
});

export const RUNNING_DISCOVERY: ForgeDiscovery = asSchema('ForgeDiscoveryView', {
    ...COMPLETED_DISCOVERY,
    id: 13,
    state: 'running',
    finishedAt: null,
    namespacesSeen: 2,
    repositoriesSeen: 15,
    requestsMade: 9,
    newCount: null,
    changedCount: null,
    goneCount: null
});

export const CONNECTION: ForgeConnection = asSchema('ForgeConnectionView', {
    id: CONNECTION_ID,
    name: 'Internal GitLab',
    kind: 'gitlab',
    edition: 'gitlab_self_managed',
    baseUrl: 'https://gitlab.example.internal',
    owner: null,
    credentialKind: 'gitlab_bot',
    scopes: ['read_api'],
    canWrite: false,
    tokenExpiresAt: '2027-03-01T00:00:00Z',
    forgeVersion: '17.4.1',
    internalNetwork: true,
    caSubject: 'CN=Example Internal Root CA',
    caNotAfter: '2030-01-01T00:00:00Z',
    encryptionState: 'current',
    state: 'active',
    integration: 'forge.gitlab',
    lastDiscovery: COMPLETED_DISCOVERY,
    importedTargets: 5,
    createdAt: '2026-10-01T09:00:00Z',
    createdBy: 'admin',
    probedAt: '2026-10-01T09:00:00Z',
    updatedAt: '2026-10-01T09:00:00Z',
    updatedBy: 'admin'
});

export function repository(forgeId: string, fullPath: string, changes: Partial<ForgeRepository> = {}): ForgeRepository {
    const parts = fullPath.split('/');
    return asSchema('ForgeRepositoryView', {
        id: Number(forgeId),
        connectionId: CONNECTION_ID,
        forgeId,
        fullPath,
        namespacePath: parts.slice(0, -1).join('/'),
        name: parts[parts.length - 1],
        defaultBranch: 'main',
        archived: false,
        fork: null,
        visibility: 'private',
        language: 'Java',
        lastActivityAt: '2026-09-28T10:00:00Z',
        sizeBytes: null,
        httpUrl: `https://gitlab.example.internal/${fullPath}.git`,
        sshUrl: `git@gitlab.example.internal:${fullPath}.git`,
        webUrl: `https://gitlab.example.internal/${fullPath}`,
        personal: false,
        firstSeenAt: '2026-10-03T08:01:00Z',
        firstSeenBy: 12,
        lastSeenAt: '2026-10-03T08:01:00Z',
        lastSeenBy: 12,
        changeSummary: null,
        ...changes
    });
}

export function candidate(repo: ForgeRepository, changes: Partial<ForgeCandidate> = {}): ForgeCandidate {
    return asSchema('ForgeCandidate', {
        repository: repo,
        selectable: true,
        notSelectable: null,
        offered: true,
        presentAs: [],
        importedAs: null,
        proposedSolution: repo.namespacePath.split('/')[0],
        proposedProject: repo.namespacePath.split('/').slice(1).join('/') || repo.namespacePath.split('/')[0],
        ...changes
    });
}

export const API = repository('101', 'acme/backend/payments/api');
export const WORKER = repository('102', 'acme/backend/payments/worker');
export const PRESENT = repository('103', 'acme/frontend/portal');
export const PERSONAL = repository('104', 'jdoe/sandbox', { personal: true });

export const CANDIDATE_PAGE: ForgeCandidatePage = asSchema('ForgeCandidatePage', {
    discoveryId: 12,
    items: [
        candidate(API),
        candidate(WORKER),
        candidate(PRESENT, {
            selectable: false,
            notSelectable: 'already_present',
            offered: false,
            presentAs: [7, 8, 9]
        }),
        candidate(PERSONAL, { offered: false, proposedSolution: null, proposedProject: null })
    ],
    limit: 50,
    offset: 0,
    listed: 37,
    total: 4,
    unjudged: { fork: 30 }
});

export const PREVIEW: ForgeImportPreview = asSchema('ForgeImportPreview', {
    connectionId: CONNECTION_ID,
    discoveryId: 12,
    targets: [
        {
            forgeId: '101',
            fullPath: 'acme/backend/payments/api',
            url: 'https://gitlab.example.internal/acme/backend/payments/api.git',
            branch: 'main',
            credential: { kind: 'https_token', id: '3b1f0c2e-6d4a-4e8b-9f10-2a7c5d9e1b44', name: 'gitlab-read' },
            solution: 'acme',
            project: 'backend/payments',
            visibleTo: 'administrators and the roles that see the whole estate, and the 2 account(s)…',
            firstScanNotBefore: null,
            warning: null
        },
        {
            forgeId: '102',
            fullPath: 'acme/backend/payments/worker',
            url: 'https://gitlab.example.internal/acme/backend/payments/worker.git',
            branch: 'main',
            credential: { kind: 'none', id: null, name: null },
            solution: null,
            project: null,
            visibleTo: 'administrators and the roles that see the whole estate — it is filed into no project',
            firstScanNotBefore: null,
            warning: 'This repository is private and is imported with no clone credential.'
        }
    ],
    skipped: [
        { forgeId: '103', fullPath: 'acme/frontend/portal', reason: 'already_present', repositoryIds: [7, 8, 9] }
    ],
    refused: [],
    solutions: [{ name: 'acme', existingId: 4 }],
    projects: [{ name: 'backend/payments', solution: 'acme', existingId: 11, targets: 1, accounts: 2, teams: 1 }],
    credentials: [
        {
            host: 'gitlab.example.internal',
            credential: { kind: 'https_token', id: '3b1f0c2e-6d4a-4e8b-9f10-2a7c5d9e1b44', name: 'gitlab-read' },
            proposed: true,
            repositories: 2
        }
    ],
    defaultIntervalDays: 7,
    visibilityMode: 'assigned',
    firstScans: null
});

export const RESULT: ForgeImportResult = asSchema('ForgeImportResult', {
    connectionId: CONNECTION_ID,
    discoveryId: 12,
    created: [
        {
            repositoryId: 41,
            forgeId: '101',
            fullPath: 'acme/backend/payments/api',
            url: 'https://gitlab.example.internal/acme/backend/payments/api.git',
            solution: 'acme',
            project: 'backend/payments',
            firstScanId: 900,
            firstScanNotBefore: '2026-10-03T09:01:00Z'
        },
        {
            repositoryId: 42,
            forgeId: '102',
            fullPath: 'acme/backend/payments/worker',
            url: 'https://gitlab.example.internal/acme/backend/payments/worker.git',
            solution: null,
            project: null,
            firstScanId: null,
            firstScanNotBefore: null
        }
    ],
    skipped: [
        { forgeId: '103', fullPath: 'acme/frontend/portal', reason: 'already_present', repositoryIds: [7, 8, 9] }
    ],
    solutionsCreated: [],
    projectsCreated: [],
    firstScans: { count: 1, spacingSeconds: 60, firstAt: '2026-10-03T09:01:00Z', lastAt: '2026-10-03T09:01:00Z' }
});
