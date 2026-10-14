import type { Issue } from '../api.models';
import { asSchema } from './contract';

/**
 * A backlog row as `GET /api/v1/issues` sends it: every field the client models present, the
 * unknown ones null — which is what the wire carries, since this server writes a null rather than
 * leaving a key out.
 *
 * <p>The backlog specs wrote rows of a dozen fields and let the rest be `undefined`. Thirty fields of
 * `Issue` were therefore something no server sends, and a template testing `!== null` would have
 * taken each for a value. `changes` holds what a case is about; the rest is a high vulnerability,
 * open and under review, with nothing known of its target or package.
 */
export function backlogEntry(id: number, changes: Partial<Issue> = {}): Issue {
    const row: Issue = {
        id,
        repoId: null,
        containerId: null,
        targetKind: 'repository',
        targetName: null,
        type: 'vulnerability',
        identifier: `CVE-2026-${id}`,
        severity: 'high',
        packageName: null,
        packageVersion: null,
        purl: null,
        filePath: null,
        line: null,
        cvssScore: null,
        epssScore: null,
        fixState: null,
        fixVersions: null,
        link: null,
        description: null,
        state: 'open',
        firstSeenAt: '2026-03-03T08:00:00Z',
        lastSeenAt: '2026-08-21T05:03:00Z',
        timesSeen: 1,
        triageStatus: 'under_review',
        triageJustification: null,
        triageComment: null,
        triagedBy: null,
        triagedAt: null,
        triageExpiresAt: null,
        triageRequestedStatus: null,
        isDirectDependency: null,
        isKev: false,
        ticketRef: null,
        ticketUrl: null,
        slaDueAt: null,
        slaState: null,
        slaDays: null,
        tool: null,
        toolName: null,
        toolVersion: null,
        importSource: null,
        ...changes
    };
    return asSchema('BacklogEntry', row);
}
