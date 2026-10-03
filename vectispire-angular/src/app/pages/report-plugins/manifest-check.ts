import type { ReportMediaType, ReportPluginManifest } from '../../core/api.models';
import { MEDIA_TYPE_EXTENSIONS } from '../../shared/report-plugins';

/**
 * What is wrong with a pasted manifest, in words, before it is sent.
 *
 * **The server stays the judge** (`ReportPluginManifest.validated()`); this repeats its rules only so
 * that the governor reads every problem at once, in their language, while the text is still in front of
 * them — the server names the first one, in English. A rule the server adds and this file lacks costs a
 * round trip, not a wrong manifest.
 */
export type ManifestProblem =
    | { key: 'report_plugins.check.not_json'; params: { error: string } }
    | { key: 'report_plugins.check.not_object'; params?: undefined }
    | { key: 'report_plugins.check.id'; params?: undefined }
    | { key: 'report_plugins.check.name'; params?: undefined }
    | { key: 'report_plugins.check.image'; params?: undefined }
    | { key: 'report_plugins.check.export_schema'; params?: undefined }
    | { key: 'report_plugins.check.arguments'; params?: undefined }
    | { key: 'report_plugins.check.media_type'; params: { types: string } }
    | { key: 'report_plugins.check.output'; params?: undefined }
    | { key: 'report_plugins.check.output_extension'; params: { extension: string } }
    | { key: 'report_plugins.check.max_output_bytes'; params: { max: number } }
    | { key: 'report_plugins.check.timeout'; params: { min: number; max: number } }
    | { key: 'report_plugins.check.signature'; params?: undefined }
    | { key: 'report_plugins.check.network'; params?: undefined }
    | { key: 'report_plugins.check.other_id'; params: { id: string } };

export const MAX_OUTPUT_BYTES = 50 * 1024 * 1024;
export const MIN_TIMEOUT_SECONDS = 10;
export const MAX_TIMEOUT_SECONDS = 300;

const ID = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;
const PINNED_IMAGE = /^[^\s@]+@sha256:[0-9a-f]{64}$/;

export interface ManifestCheck {
    manifest: ReportPluginManifest | null;
    problems: ManifestProblem[];
}

/**
 * @param text what was pasted
 * @param expectedId for a new manifest of an existing plugin: the id it must keep — documents name it
 */
export function checkManifest(text: string, expectedId: string | null = null): ManifestCheck {
    let parsed: unknown;
    try {
        parsed = JSON.parse(text);
    } catch (error) {
        return {
            manifest: null,
            problems: [{ key: 'report_plugins.check.not_json', params: { error: String(error) } }]
        };
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return { manifest: null, problems: [{ key: 'report_plugins.check.not_object' }] };
    }
    const value = parsed as Record<string, unknown>;
    const problems: ManifestProblem[] = [];
    const text_ = (field: string): string | null => {
        const one = value[field];
        return typeof one === 'string' && one.trim() ? one.trim() : null;
    };
    const integer = (field: string): number | null | undefined =>
        value[field] === undefined || value[field] === null
            ? undefined
            : Number.isInteger(value[field])
              ? (value[field] as number)
              : null;

    const id = text_('id');
    if (!id || !ID.test(id)) problems.push({ key: 'report_plugins.check.id' });
    else if (expectedId !== null && id !== expectedId)
        problems.push({ key: 'report_plugins.check.other_id', params: { id: expectedId } });
    if (!text_('name') || (text_('name') ?? '').length > 100) problems.push({ key: 'report_plugins.check.name' });
    if (!PINNED_IMAGE.test(text_('image') ?? '')) problems.push({ key: 'report_plugins.check.image' });
    const exportSchema = integer('export_schema');
    if (exportSchema === undefined || exportSchema === null || exportSchema < 1) {
        problems.push({ key: 'report_plugins.check.export_schema' });
    }
    const args = value['arguments'];
    if (args !== undefined && (!Array.isArray(args) || args.some((one) => typeof one !== 'string'))) {
        problems.push({ key: 'report_plugins.check.arguments' });
    }
    const mediaType = value['media_type'];
    const known = typeof mediaType === 'string' && Object.hasOwn(MEDIA_TYPE_EXTENSIONS, mediaType);
    if (!known) {
        problems.push({
            key: 'report_plugins.check.media_type',
            params: { types: Object.values(MEDIA_TYPE_EXTENSIONS).join(', ') }
        });
    }
    const output = text_('output');
    if (!output || output.includes('/') || output.includes('\\') || output.startsWith('.')) {
        problems.push({ key: 'report_plugins.check.output' });
    } else if (known) {
        const extension = MEDIA_TYPE_EXTENSIONS[mediaType as ReportMediaType];
        if (!output.toLowerCase().endsWith(extension)) {
            problems.push({ key: 'report_plugins.check.output_extension', params: { extension } });
        }
    }
    const maxOutput = integer('max_output_bytes');
    if (maxOutput === null || (maxOutput !== undefined && (maxOutput < 1 || maxOutput > MAX_OUTPUT_BYTES))) {
        problems.push({ key: 'report_plugins.check.max_output_bytes', params: { max: MAX_OUTPUT_BYTES } });
    }
    const timeout = integer('timeout_seconds');
    if (
        timeout === null ||
        (timeout !== undefined && (timeout < MIN_TIMEOUT_SECONDS || timeout > MAX_TIMEOUT_SECONDS))
    ) {
        problems.push({
            key: 'report_plugins.check.timeout',
            params: { min: MIN_TIMEOUT_SECONDS, max: MAX_TIMEOUT_SECONDS }
        });
    }
    if (!signerDeclared(value['signature'])) problems.push({ key: 'report_plugins.check.signature' });
    // Said rather than ignored: a governor pasting a scanner plugin's manifest expects the field to mean something.
    if ('network' in value || 'network_justification' in value) problems.push({ key: 'report_plugins.check.network' });

    return { manifest: problems.length === 0 ? (value as unknown as ReportPluginManifest) : null, problems };
}

/** Keyless (identity and issuer, both) or a public key — exactly one of the two, as the server requires. */
function signerDeclared(signature: unknown): boolean {
    if (signature === null || typeof signature !== 'object') return false;
    const { identity, issuer, public_key: key } = signature as Record<string, unknown>;
    const has = (field: unknown) => typeof field === 'string' && field.trim().length > 0;
    const keyless = has(identity) && has(issuer);
    return keyless !== has(key) && (keyless || (!has(identity) && !has(issuer)));
}
