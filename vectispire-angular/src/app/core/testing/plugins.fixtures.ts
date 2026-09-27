import type { Plugin, PluginActivation, PluginManifest, SarifSource } from '../api.models';
import { asSchema } from './contract';

/**
 * The plugins module's shapes, as the control plane publishes them, for the specs of the clients
 * and of the screens that read them. Checked against the document on load: a fixture that drifts
 * from the server fails where it is declared, not in the screen that happened to use it.
 */
export const MANIFEST: PluginManifest = asSchema('PluginManifest', {
    id: 'acme-lint',
    name: 'ACME house rules',
    image: `registry.acme.internal/sec/acme-lint@sha256:${'a'.repeat(64)}`,
    languages: ['java', 'kotlin'],
    arguments: ['--sarif', '{output}', '{source}'],
    output: 'results.sarif',
    exit_codes: [0, 1],
    network: false,
    network_justification: null,
    timeout_seconds: 600
});

export const PLUGIN: Plugin = asSchema('PluginView', {
    id: 'acme-lint',
    name: 'ACME house rules',
    manifest: MANIFEST,
    manifestDigest: 'b'.repeat(64),
    enabled: true,
    createdAt: '2026-09-27T08:00:00Z',
    createdBy: 'admin',
    updatedAt: null,
    updatedBy: null
});

export const ACTIVATION: PluginActivation = asSchema('PluginActivationView', {
    id: 1,
    pluginId: 'acme-lint',
    projectId: 12,
    activatedAt: '2026-09-27T09:00:00Z',
    activatedBy: 'ciso'
});

export const SOURCE: SarifSource = asSchema('SarifSourceView', {
    id: 3,
    slug: 'payments-ci',
    name: 'Payments CI',
    apiKeyId: '5f0c3c1e-0000-4000-8000-000000000001',
    projectId: 12,
    repositoryId: null,
    tools: ['Semgrep OSS', 'SonarQube'],
    enabled: true,
    createdAt: '2026-09-27T08:00:00Z',
    createdBy: 'admin'
});
