import type {
    ReportPlugin,
    ReportPluginActivation,
    ReportPluginManifest,
    ReportPluginManifestView,
    ReportRun
} from '../api.models';
import { asSchema } from './contract';

/**
 * Report plugins' shapes (decision 0035), as the control plane publishes them, checked against the
 * document on load: a fixture that drifts from the server fails where it is declared.
 */
export const REPORT_MANIFEST: ReportPluginManifest = asSchema('ReportPluginManifest', {
    id: 'quarterly-summary',
    name: 'Quarterly risk summary',
    image: `registry.example.internal/reports/quarterly-summary@sha256:${'4'.repeat(64)}`,
    export_schema: 1,
    arguments: ['--in', '{input}', '--out', '{output}'],
    output: 'summary.xlsx',
    media_type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    max_output_bytes: 20971520,
    timeout_seconds: 120,
    signature: {
        identity: 'https://ci.example.internal/reports/quarterly-summary/release@refs/tags/v2.1.0',
        issuer: 'https://ci.example.internal/oidc',
        public_key: null
    }
});

export const APPROVED_DIGEST = 'a'.repeat(64);
export const PENDING_DIGEST = 'b'.repeat(64);

export const APPROVED_MANIFEST: ReportPluginManifestView = asSchema('ReportPluginManifestView', {
    digest: APPROVED_DIGEST,
    status: 'approved',
    manifest: REPORT_MANIFEST,
    registeredAt: '2026-10-01T08:00:00Z',
    registeredBy: 'governor',
    approvedAt: '2026-10-01T09:00:00Z',
    approvedBy: 'ciso',
    approvalFourEyes: true,
    withdrawnAt: null,
    withdrawnBy: null,
    withdrawalJustification: null
});

/** Registered by `governor`, waiting for somebody else. */
export const PENDING_MANIFEST: ReportPluginManifestView = asSchema('ReportPluginManifestView', {
    ...APPROVED_MANIFEST,
    digest: PENDING_DIGEST,
    status: 'pending_approval',
    manifest: { ...REPORT_MANIFEST, timeout_seconds: 200 },
    registeredAt: '2026-10-02T08:00:00Z',
    approvedAt: null,
    approvedBy: null,
    approvalFourEyes: null
});

export const REPORT_PLUGIN: ReportPlugin = asSchema('ReportPluginView', {
    id: 'quarterly-summary',
    name: 'Quarterly risk summary',
    approvedDigest: APPROVED_DIGEST,
    pendingDigest: PENDING_DIGEST,
    enabled: true,
    createdAt: '2026-10-01T08:00:00Z',
    createdBy: 'governor',
    updatedAt: '2026-10-02T08:00:00Z',
    updatedBy: 'governor',
    manifests: [PENDING_MANIFEST, APPROVED_MANIFEST]
});

/** Registered, never approved: nothing can switch it on. */
export const UNAPPROVED_PLUGIN: ReportPlugin = asSchema('ReportPluginView', {
    ...REPORT_PLUGIN,
    id: 'draft-pdf',
    name: 'Draft PDF',
    approvedDigest: null,
    manifests: [PENDING_MANIFEST]
});

export const REPORT_ACTIVATION: ReportPluginActivation = asSchema('ReportPluginActivationView', {
    id: 1,
    pluginId: 'quarterly-summary',
    pluginName: 'Quarterly risk summary',
    projectId: 12,
    activatedAt: '2026-10-02T10:00:00Z',
    activatedBy: 'ciso'
});

export const PRODUCED_RUN: ReportRun = asSchema('ReportRunView', {
    id: 34,
    projectId: 12,
    projectName: 'Gateway',
    pluginId: 'quarterly-summary',
    state: 'produced',
    reason: null,
    detail: null,
    requestedAt: '2026-10-03T08:00:00Z',
    requestedBy: 'auditor',
    startedAt: '2026-10-03T08:00:05Z',
    exportedAt: '2026-10-03T08:00:06Z',
    finishedAt: '2026-10-03T08:00:30Z',
    manifestDigest: APPROVED_DIGEST,
    imageDigest: `sha256:${'4'.repeat(64)}`,
    signerIdentity: REPORT_MANIFEST.signature.identity,
    signerIssuer: REPORT_MANIFEST.signature.issuer,
    signerKeySha256: null,
    exportSchemaVersion: '1.0',
    exportSha256: 'c'.repeat(64),
    exportSize: 48000,
    exitCode: 0,
    outputSize: 2 * 1024 * 1024,
    outputSha256: 'd'.repeat(64),
    outputMediaType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    signingKeyId: 'key-1',
    packageSha256: 'e'.repeat(64),
    productVersion: '0.11.0'
});

export const PENDING_RUN: ReportRun = asSchema('ReportRunView', {
    ...PRODUCED_RUN,
    id: 35,
    state: 'pending',
    startedAt: null,
    exportedAt: null,
    finishedAt: null,
    manifestDigest: null,
    imageDigest: null,
    signerIdentity: null,
    signerIssuer: null,
    exportSchemaVersion: null,
    exportSha256: null,
    exportSize: null,
    exitCode: null,
    outputSize: null,
    outputSha256: null,
    outputMediaType: null,
    signingKeyId: null,
    packageSha256: null
});

export const FAILED_RUN: ReportRun = asSchema('ReportRunView', {
    ...PENDING_RUN,
    id: 33,
    state: 'failed',
    reason: 'exit_code',
    detail: 'the export has no issues part',
    exitCode: 1,
    finishedAt: '2026-10-02T08:00:30Z'
});

export const REFUSED_RUN: ReportRun = asSchema('ReportRunView', {
    ...PENDING_RUN,
    id: 32,
    state: 'refused',
    reason: 'signature_unverified',
    detail: 'no matching signatures',
    finishedAt: '2026-10-01T08:00:30Z'
});

// Held in a constant: the label ratchet reads `title: '…'` in any `.ts` under src/app as a frozen label.
const CONFLICT = 'Conflict';

/** A problem as the server answers a 409 of this module (`urn:vectispire:problem:<token>`). */
export function reportConflict(token: string, detail = 'Refused.'): object {
    return { type: `urn:vectispire:problem:${token}`, title: CONFLICT, status: 409, detail };
}
