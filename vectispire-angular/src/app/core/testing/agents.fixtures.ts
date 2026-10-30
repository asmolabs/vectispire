import type {
    AgentActivitySummary,
    AgentSummary,
    PendingScanItem,
    RunningScanItem,
    UnservedCredentialedScans
} from '../api.models';
import { asSchema } from './contract';

/** An agent as `GET /api/v1/admin/agents` sends it: online, idle, local credentials, limit 4. */
export function agentSummary(changes: Partial<AgentSummary> = {}): AgentSummary {
    return asSchema('AgentSummary', {
        id: '00000000-0000-0000-0000-0000000000aa',
        name: 'runner-dmz-01',
        kind: 'remote',
        enabled: true,
        credentialsMode: 'local',
        sealsCredentials: false,
        signsResults: false,
        maxConcurrent: 4,
        online: true,
        runningScans: 0,
        description: null,
        labels: null,
        hostname: 'runner-dmz-01',
        platform: 'linux/amd64',
        version: '0.9.0',
        contractVersion: '1',
        lastSeenAt: '2026-09-26T05:00:00Z',
        ...changes
    });
}

export function runningScan(changes: Partial<RunningScanItem> = {}): RunningScanItem {
    return asSchema('RunningScanItem', {
        scanId: 7,
        targetType: 'repository' as const,
        targetId: 3,
        targetName: 'billing-api',
        branch: 'main',
        agentName: 'runner-dmz-01',
        claimedAt: '2026-09-26T05:00:00Z',
        agentId: '00000000-0000-0000-0000-0000000000aa',
        requiredLabel: null,
        durationSeconds: 40,
        ...changes
    });
}

export function pendingScan(changes: Partial<PendingScanItem> = {}): PendingScanItem {
    return asSchema('PendingScanItem', {
        scanId: 8,
        targetType: 'repository' as const,
        targetId: 4,
        targetName: 'ledger',
        branch: 'main',
        queuedAt: '2026-09-26T05:01:00Z',
        requiredLabel: null,
        isRoutable: true,
        positionInQueue: 1,
        waitDurationSeconds: 12,
        ...changes
    });
}

/** The fleet's activity, its figures counted from the scans given unless overridden. */
export function agentActivity(
    runningScans: RunningScanItem[] = [],
    pendingScans: PendingScanItem[] = [],
    stats: Partial<AgentActivitySummary['stats']> = {}
): AgentActivitySummary {
    return asSchema('AgentActivitySummary', {
        runningScans,
        pendingScans,
        stats: {
            avgScanDurationSeconds: 0,
            busyAgents: 0,
            idleAgents: 0,
            onlineAgents: 0,
            pendingScansCount: pendingScans.length,
            runningScansCount: runningScans.length,
            scansCompleted24h: 0,
            totalAgents: 0,
            ...stats
        }
    });
}

export const NO_CREDENTIALED_BACKLOG: UnservedCredentialedScans = asSchema('UnservedCredentialedScans', {
    scans: 0,
    labels: [],
    keptAgents: []
});
