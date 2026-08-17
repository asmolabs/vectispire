import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CSV_COLUMNS, ExportableIssue, buildIssuesCsv, buildOpenVexDocument, buildSarifDocument } from './exports';

interface ExportVector {
    label: string;
    issues: ExportableIssue[];
    sarif: Record<string, unknown>;
    openvex: Record<string, unknown>;
    csv: string;
}

/**
 * JSON carries no date type: the instants in the vector file are strings and have to
 * become `Date`s again, as the database returns them. Without this step, the test would
 * not exercise the same code as production.
 */
const INSTANT_FIELDS = ['firstSeenAt', 'lastSeenAt', 'triagedAt', 'triageExpiresAt'] as const;

function reviveInstants(issue: Record<string, unknown>): ExportableIssue {
    const revived = { ...issue };
    for (const field of INSTANT_FIELDS) {
        const value = revived[field];
        if (typeof value === 'string') revived[field] = new Date(value.endsWith('Z') ? value : `${value}Z`);
    }
    return revived as unknown as ExportableIssue;
}

const raw: { cases: (Omit<ExportVector, 'issues'> & { issues: Record<string, unknown>[] })[]; sarifWithoutInformationUri: Record<string, unknown> } = JSON.parse(
    readFileSync(join(__dirname, '../../../test/vectors/exports.json'), 'utf8')
);
const vectors = { ...raw, cases: raw.cases.map((vector) => ({ ...vector, issues: vector.issues.map(reviveInstants) })) };

const SARIF_OPTIONS = { targetName: 'org/example', toolVersion: '1.2.3', informationUri: 'https://zanshin.internal' };
const VEX_OPTIONS = {
    author: 'Zanshin <security@example.com>',
    productId: 'pkg:github/org/example',
    documentId: 'https://zanshin.internal/vex/1',
    timestamp: new Date('2026-08-10T08:00:00Z'),
    version: 3
};

describe('exports', () => {
    // The vectors came from the Python code; they are now regenerated from this
    // implementation and serve as a guard against a format regression, not as proof of
    // equivalence with another language.
    it('has vectors to compare against', () => {
        expect(vectors.cases.length).toBeGreaterThan(0);
    });

    describe.each(vectors.cases)('$label', (vector) => {
        it('returns the same SARIF document', () => {
            expect(buildSarifDocument(vector.issues, SARIF_OPTIONS)).toEqual(vector.sarif);
        });

        it('returns the same OpenVEX document', () => {
            expect(buildOpenVexDocument(vector.issues, VEX_OPTIONS)).toEqual(vector.openvex);
        });

        it('returns the same CSV, byte for byte', () => {
            expect(buildIssuesCsv(vector.issues)).toBe(vector.csv);
        });
    });

    it("omits informationUri rather than writing it null", () => {
        // `**({...} if x else {})` in Python: the key is absent, not null. A strict
        // consumer of the schema refuses `"informationUri": null`.
        const document = buildSarifDocument([vectors.cases[1].issues[0]], { targetName: 'org/example', toolVersion: '1.2.3' });
        expect(document).toEqual(vectors.sarifWithoutInformationUri);
        const driver = (document.runs as { tool: { driver: Record<string, unknown> } }[])[0].tool.driver;
        expect('informationUri' in driver).toBe(false);
    });
});

describe('the format details a port gets wrong', () => {
    const issue = vectors.cases[1].issues[0];

    it('terminates CSV rows with CRLF, including the last one', () => {
        const csv = buildIssuesCsv([issue]);
        expect(csv.endsWith('\r\n')).toBe(true);
        expect(csv.split('\r\n').filter(Boolean)).toHaveLength(2);
        // No lone \n: that would be a file most tools would read anyway, hence a
        // divergence nobody would notice until a strict consumer refused it.
        expect(csv.replace(/\r\n/g, '')).not.toContain('\n');
    });

    it("writes whole scores with their decimal, like str(float) in Python", () => {
        const row = buildIssuesCsv([{ ...issue, cvssScore: 9, epssScore: 1 }]).split('\r\n')[1].split(',');
        expect(row[4]).toBe('9.0');
        expect(row[5]).toBe('1.0');
    });

    it('tells a zero score from an absent one', () => {
        const withZero = buildIssuesCsv([{ ...issue, cvssScore: 0, epssScore: 0 }]).split('\r\n')[1].split(',');
        expect(withZero[4]).toBe('0.0');
        const withNull = buildIssuesCsv([{ ...issue, cvssScore: null, epssScore: null }]).split('\r\n')[1].split(',');
        expect(withNull[4]).toBe('');
    });

    it('quotes a field containing a comma, a quote or a newline', () => {
        const csv = buildIssuesCsv([{ ...issue, triageComment: null, link: 'a,b' }]);
        expect(csv).toContain('"a,b"');
        expect(buildIssuesCsv([{ ...issue, link: 'a"b' }])).toContain('"a""b"');
        expect(buildIssuesCsv([{ ...issue, link: 'a\nb' }])).toContain('"a\nb"');
    });

    it('does not quote what does not need it', () => {
        expect(buildIssuesCsv([{ ...issue, link: 'simple' }])).toContain(',simple');
    });

    it('has exactly Python\'s 25 columns, in order', () => {
        expect(CSV_COLUMNS).toHaveLength(25);
        expect(buildIssuesCsv([]).trim()).toBe(CSV_COLUMNS.join(','));
    });
});

describe('the SARIF invariants, which decide what GitHub displays', () => {
    const issue = vectors.cases[1].issues[0];
    const runs = (document: Record<string, unknown>) => (document.runs as { results: Record<string, unknown>[]; tool: { driver: { rules: Record<string, unknown>[] } } }[])[0];

    it('gives every result a location, even with no file', () => {
        // GitHub silently discards results with no location. An "honestly empty"
        // location would make most of the vulnerabilities disappear.
        const document = buildSarifDocument([{ ...issue, filePath: null, line: null }], SARIF_OPTIONS);
        const locations = runs(document).results[0].locations as { physicalLocation: { artifactLocation: { uri: string } } }[];
        expect(locations).toHaveLength(1);
        expect(locations[0].physicalLocation.artifactLocation.uri).toBe('.');
    });

    it('suppresses triaged issues instead of omitting them', () => {
        // Removing them would make a platform report them as new on the next upload,
        // undoing the triage work.
        const triaged = { ...issue, triageStatus: 'not_affected', triageJustification: 'component_not_present' };
        const results = runs(buildSarifDocument([triaged], SARIF_OPTIONS)).results;
        expect(results).toHaveLength(1);
        expect(results[0].suppressions).toBeDefined();
    });

    it('does not suppress an affected: deciding an issue is real must stay visible', () => {
        const results = runs(buildSarifDocument([{ ...issue, triageStatus: 'affected' }], SARIF_OPTIONS)).results;
        expect(results[0].suppressions).toBeUndefined();
    });

    it('tags quality as quality and not as security', () => {
        // Without this, every quality finding would be reported into GitHub code
        // scanning as a security alert.
        const rules = runs(buildSarifDocument([{ ...issue, type: 'quality' }], SARIF_OPTIONS)).tool.driver.rules;
        expect((rules[0].properties as { tags: string[] }).tags).toEqual(['quality', 'quality']);
    });

    it('carries security-severity, which is what GitHub actually sorts on', () => {
        const rules = runs(buildSarifDocument([{ ...issue, severity: 'critical' }], SARIF_OPTIONS)).tool.driver.rules;
        expect((rules[0].properties as Record<string, unknown>)['security-severity']).toBe('9.5');
    });

    it('does not invent a security-severity for a severity outside the vocabulary', () => {
        const rules = runs(buildSarifDocument([{ ...issue, severity: 'catastrophic' }], SARIF_OPTIONS)).tool.driver.rules;
        expect((rules[0].properties as Record<string, unknown>)['security-severity']).toBeUndefined();
    });

    it('numbers the rules in their order of appearance', () => {
        // `ruleIndex` points into the `rules` array: a desynchronization would display
        // the wrong rule under each result.
        const document = buildSarifDocument(
            [
                { ...issue, id: 1, identifier: 'CVE-A' },
                { ...issue, id: 2, identifier: 'CVE-B' },
                { ...issue, id: 3, identifier: 'CVE-A' }
            ],
            SARIF_OPTIONS
        );
        const { results, tool } = runs(document);
        expect(tool.driver.rules).toHaveLength(2);
        expect(results.map((result) => result.ruleIndex)).toEqual([0, 1, 0]);
        for (const result of results) {
            expect(tool.driver.rules[result.ruleIndex as number].id).toBe(result.ruleId);
        }
    });
});

describe('the OpenVEX invariants', () => {
    const issue = vectors.cases[1].issues[0];
    const statements = (document: Record<string, unknown>) => document.statements as Record<string, unknown>[];

    it('emits a statement only for an identified vulnerability', () => {
        expect(statements(buildOpenVexDocument([{ ...issue, type: 'secret' }], VEX_OPTIONS))).toHaveLength(0);
        expect(statements(buildOpenVexDocument([{ ...issue, identifier: null }], VEX_OPTIONS))).toHaveLength(0);
    });

    it('declares a resolved, never-triaged issue as fixed', () => {
        // Saying "under investigation" about something the scanner no longer sees would
        // be misleading in a document made to answer exactly that.
        const [statement] = statements(buildOpenVexDocument([{ ...issue, state: 'resolved', triageStatus: 'under_review' }], VEX_OPTIONS));
        expect(statement.status).toBe('fixed');
    });

    it('maps under_review to under_investigation, the only vocabulary difference', () => {
        const [statement] = statements(buildOpenVexDocument([issue], VEX_OPTIONS));
        expect(statement.status).toBe('under_investigation');
    });

    it('carries the justification the specification requires for not_affected', () => {
        const [statement] = statements(buildOpenVexDocument([{ ...issue, triageStatus: 'not_affected', triageJustification: 'component_not_present' }], VEX_OPTIONS));
        expect(statement.justification).toBe('component_not_present');
    });

    it('files the free text under impact_statement or action_statement depending on status', () => {
        const notAffected = statements(buildOpenVexDocument([{ ...issue, triageStatus: 'not_affected', triageJustification: 'j', triageComment: 'text' }], VEX_OPTIONS))[0];
        expect(notAffected.impact_statement).toBe('text');
        expect(notAffected.action_statement).toBeUndefined();

        const affected = statements(buildOpenVexDocument([{ ...issue, triageStatus: 'affected', triageComment: 'text' }], VEX_OPTIONS))[0];
        expect(affected.action_statement).toBe('text');
        expect(affected.impact_statement).toBeUndefined();
    });
});

describe('CSV and formula injection', () => {
    /** An issue whose fields come from a scanned repository, hence from outside. */
    function hostile(over: Record<string, unknown> = {}) {
        return {
            id: 1,
            repoId: 1,
            containerId: null,
            type: 'vulnerability',
            identifier: 'CVE-2021-44228',
            severity: 'high',
            state: 'open',
            triageStatus: 'under_review',
            packageName: "=cmd|'/c calc.exe'!A1",
            packageVersion: '1.0',
            purl: null,
            filePath: null,
            source: 'grype',
            epssScore: null,
            isKev: false,
            cvssScore: null,
            cvssVector: null,
            fixState: null,
            fixVersions: null,
            link: null,
            description: null,
            firstSeenAt: new Date('2026-01-01T00:00:00Z'),
            lastSeenAt: new Date('2026-01-01T00:00:00Z'),
            timesSeen: 1,
            triageJustification: null,
            triageComment: null,
            triagedBy: null,
            triagedAt: null,
            isDirectDependency: null,
            line: null,
            ticketRef: null,
            ticketUrl: null,
            ...over
        } as never;
    }

    it("neutralizes a package name that is a formula", () => {
        // The reader of this file is a security operator opening it in a spreadsheet —
        // which is the very point of the export. A package named this way would execute
        // on their machine.
        const csv = buildIssuesCsv([hostile()]);

        expect(csv).toContain("'=cmd|'/c calc.exe'!A1");
        expect(csv).not.toMatch(/(^|,)=cmd/m);
    });

    it.each(['=1+1', '+1+1', '-1+1', '@SUM(1)', '\t=1+1', '\r=1+1'])('neutralizes the %j prefix', (payload) => {
        const csv = buildIssuesCsv([hostile({ packageName: payload })]);

        // The value still appears, preceded by the apostrophe that forces text mode — and
        // never bare. The test looks at the produced value rather than at a split into
        // rows, which a carriage return inside the field would make wrong.
        expect(csv).toContain(`'${payload}`);
        expect(csv.includes(`,${payload}`)).toBe(false);
        expect(csv.includes(`,"${payload}`)).toBe(false);
    });

    it('does not neutralize what is harmless', () => {
        // Blanket neutralization would damage every cell and make the export tiresome to
        // use — the goal is to block formulas, not to prefix the whole file.
        const csv = buildIssuesCsv([hostile({ packageName: 'log4j-core' })]);

        expect(csv).toContain('log4j-core');
        expect(csv).not.toContain("'log4j-core");
    });

    it("also neutralizes a field that must be quoted, since quoting does not protect", () => {
        // The spreadsheet strips the quotes before evaluating: quoting is not enough, and
        // that is the trap that makes the problem look solved.
        const csv = buildIssuesCsv([hostile({ packageName: '=HYPERLINK("http://x","a"),b' })]);

        expect(csv).toContain('"\'=HYPERLINK');
    });
});
