import { MAX_DETAILED_ISSUES, type NotifiableIssue, buildPayload, selectNotable } from './payload';

function issue(values: Partial<NotifiableIssue>): NotifiableIssue {
    return {
        id: 1,
        identifier: 'CVE-2021-44228',
        type: 'vulnerability',
        severity: 'high',
        isKev: false,
        epssScore: null,
        packageName: null,
        filePath: null,
        fixVersions: null,
        link: null,
        ...values
    };
}

describe('selectNotable', () => {
    const options = { minSeverity: 'high', alwaysOnKev: true };

    it('keeps what reaches the threshold', () => {
        const selected = selectNotable([issue({ severity: 'critical' }), issue({ severity: 'low' })], options);

        expect(selected).toHaveLength(1);
        expect(selected[0].severity).toBe('critical');
    });

    it('keeps an exploited vulnerability under the threshold', () => {
        // The whole point of the KEV signal: severity alone would discard a "medium"
        // being exploited today.
        const selected = selectNotable([issue({ severity: 'medium', isKev: true })], options);

        expect(selected).toHaveLength(1);
    });

    it('respects the setting when KEV does not take precedence', () => {
        expect(selectNotable([issue({ severity: 'medium', isKev: true })], { minSeverity: 'high', alwaysOnKev: false })).toEqual([]);
    });

    it("never sends a quality finding, even above the threshold", () => {
        // Semgrep traduit `ERROR` en `high` : sans cette exclusion, le premier scan d'un
        // repository with SAST enabled would fire a webhook announcing hundreds of
        // issues, and the channel would be filtered out the next day.
        const selected = selectNotable([issue({ type: 'quality', severity: 'critical' }), issue({ type: 'quality', isKev: true })], options);

        expect(selected).toEqual([]);
    });
});

describe('buildPayload', () => {
    const base = { targetName: 'org/projet', scanId: 42, resolvedCount: 0, minSeverity: 'high' };

    it('puts a readable sentence first, for receivers that read only that', () => {
        const payload = buildPayload({
            ...base,
            newIssues: [issue({}), issue({ id: 2, isKev: true })],
            reopenedIssues: [issue({ id: 3 })],
            resolvedCount: 4
        });

        expect(payload.text).toBe('Zanshin — org/projet: 2 new issue(s), 1 reappeared, 1 actively exploited (4 resolved)');
        expect(payload.kev_count).toBe(1);
        expect(payload.new_count).toBe(2);
        expect(payload.reopened_count).toBe(1);
        expect(payload.resolved_count).toBe(4);
    });

    it('bounds the detail and says how many are missing', () => {
        // A body with four hundred entries is a denial of service against its reader.
        const many = Array.from({ length: 25 }, (_, index) => issue({ id: index }));
        const payload = buildPayload({ ...base, newIssues: many, reopenedIssues: [] });

        expect(payload.issues).toHaveLength(MAX_DETAILED_ISSUES);
        expect(payload.truncated).toBe(15);
    });

    it("exposes only an issue's intended fields", () => {
        // The payload leaves for a third-party system: the projection is explicit so that
        // a column added to `Issue` one day does not reach it by accident.
        const payload = buildPayload({ ...base, newIssues: [issue({ fixVersions: '2.17.1' })], reopenedIssues: [] });

        expect(Object.keys((payload.issues as unknown[])[0] as object).sort()).toEqual([
            'epss_score',
            'file_path',
            'fix_versions',
            'id',
            'identifier',
            'is_kev',
            'link',
            'package',
            'severity',
            'type'
        ]);
    });
});
