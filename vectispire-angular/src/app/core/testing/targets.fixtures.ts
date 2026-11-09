import type { MonitoredContainer, MonitoredRepository } from '../api.models';
import { asSchema } from './contract';

/**
 * A monitored repository as `GET /api/v1/repositories` lists it: every field the client models
 * present, the ones a case does not set null — the server writes a null rather than leaving a key out.
 *
 * <p>Screens that only offer targets in a filter (licences, OWASP) listed repositories of five or six
 * fields, and an absent `lastScan` or `detectedLanguages` is `undefined`, which no server sends and
 * which a template reading `=== null` takes for a value.
 */
export function repositorySummary(id: number, changes: Partial<MonitoredRepository> = {}): MonitoredRepository {
    const repository: MonitoredRepository = {
        id,
        url: `ssh://git@example.invalid/repository-${id}.git`,
        branch: 'main',
        displayName: `repository-${id}`,
        name: null,
        subPath: null,
        scanIntervalMinutes: null,
        scanCron: null,
        scanManualOnly: false,
        requiredAgentLabel: null,
        sshKeyId: null,
        httpsTokenId: null,
        lastScan: null,
        openIssues: 0,
        detectedLanguages: null,
        ...changes
    };
    return asSchema('RepositorySummary', repository);
}

/** A monitored image as `GET /api/v1/containers` lists it, on the same terms. */
export function containerSummary(id: number, changes: Partial<MonitoredContainer> = {}): MonitoredContainer {
    const container: MonitoredContainer = {
        id,
        imageName: `image-${id}`,
        tag: '1.0',
        reference: `registry.invalid/image-${id}:1.0`,
        registry: null,
        scanIntervalMinutes: null,
        scanCron: null,
        scanManualOnly: false,
        requiredAgentLabel: null,
        lastScan: null,
        openIssues: 0,
        ...changes
    };
    return asSchema('ContainerSummary', container);
}
