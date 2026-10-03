import { describe, expect, it } from 'vitest';
import { missingFromBundles } from '@/app/core/testing/bundles';
import { REPORT_MANIFEST } from '@/app/core/testing/report-plugins.fixtures';
import { MAX_OUTPUT_BYTES, checkManifest } from './manifest-check';

/**
 * The pasted manifest's check: the server's rules, repeated to say every problem at once and in words.
 * A manifest the server would accept must read correctly here — a form that refuses a valid manifest is
 * worse than none — so the fixture, held to the published schema, is the first case.
 */
function without(value: object, ...fields: string[]): object {
    return Object.fromEntries(Object.entries(value).filter(([field]) => !fields.includes(field)));
}

describe('a pasted report plugin manifest', () => {
    const keys = (value: object, expectedId: string | null = null) =>
        checkManifest(JSON.stringify(value), expectedId).problems.map((problem) => problem.key);

    it('reads correctly when it is a manifest the server accepts, its optional bounds left out', () => {
        expect(checkManifest(JSON.stringify(REPORT_MANIFEST)).manifest).toEqual(REPORT_MANIFEST);
        expect(keys(without(REPORT_MANIFEST, 'max_output_bytes', 'timeout_seconds'))).toEqual([]);
        expect(keys({ ...REPORT_MANIFEST, signature: { public_key: '-----BEGIN PUBLIC KEY-----' } })).toEqual([]);
    });

    it('refuses what is not a JSON object', () => {
        expect(checkManifest('[1]').problems.map((one) => one.key)).toEqual(['report_plugins.check.not_object']);
        expect(checkManifest('{').problems[0].key).toBe('report_plugins.check.not_json');
        expect(checkManifest('{').manifest).toBeNull();
    });

    it('names each field the server would refuse', () => {
        expect(keys({ ...REPORT_MANIFEST, id: 'Quarterly' })).toEqual(['report_plugins.check.id']);
        expect(keys({ ...REPORT_MANIFEST, image: 'registry/x:1.0' })).toEqual(['report_plugins.check.image']);
        expect(keys({ ...REPORT_MANIFEST, export_schema: 0 })).toEqual(['report_plugins.check.export_schema']);
        expect(keys({ ...REPORT_MANIFEST, arguments: ['--in', 1] })).toEqual(['report_plugins.check.arguments']);
        expect(keys({ ...REPORT_MANIFEST, media_type: 'text/html', output: 'a.html' })).toEqual([
            'report_plugins.check.media_type'
        ]);
        expect(keys({ ...REPORT_MANIFEST, output: '../summary.xlsx' })).toEqual(['report_plugins.check.output']);
        expect(keys({ ...REPORT_MANIFEST, output: 'summary.xlsm' })).toEqual(['report_plugins.check.output_extension']);
        expect(keys({ ...REPORT_MANIFEST, max_output_bytes: MAX_OUTPUT_BYTES + 1 })).toEqual([
            'report_plugins.check.max_output_bytes'
        ]);
        expect(keys({ ...REPORT_MANIFEST, timeout_seconds: 301 })).toEqual(['report_plugins.check.timeout']);
        expect(keys({ ...REPORT_MANIFEST, network: false })).toEqual(['report_plugins.check.network']);
    });

    it('requires a signer, keyless or by key and not both, with no waiver', () => {
        expect(keys(without(REPORT_MANIFEST, 'signature'))).toEqual(['report_plugins.check.signature']);
        expect(keys({ ...REPORT_MANIFEST, signature: { identity: 'x' } })).toEqual(['report_plugins.check.signature']);
        expect(
            keys({ ...REPORT_MANIFEST, signature: { ...REPORT_MANIFEST.signature, public_key: '-----BEGIN' } })
        ).toEqual(['report_plugins.check.signature']);
    });

    it('holds a new manifest to the id of the plugin it updates', () => {
        expect(keys(REPORT_MANIFEST, 'another')).toEqual(['report_plugins.check.other_id']);
        expect(keys(REPORT_MANIFEST, 'quarterly-summary')).toEqual([]);
    });

    it('words every problem in both bundles', () => {
        const every = checkManifest(
            JSON.stringify({ id: 'X', image: 'x', export_schema: 0, arguments: 1, output: '', network: true })
        ).problems.map((problem) => problem.key);
        expect(every.length).toBeGreaterThan(8);
        expect(
            missingFromBundles([...every, 'report_plugins.check.not_json', 'report_plugins.check.not_object'])
        ).toEqual([]);
    });
});
