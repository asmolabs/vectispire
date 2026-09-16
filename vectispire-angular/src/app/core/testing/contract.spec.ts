import { describe, expect, it } from 'vitest';
import { asSchema, asSchemaList } from './contract';

/**
 * The checker that reads a fixture against the control plane's own document.
 *
 * <p><b>Its cases are the failures this session actually found</b>, not invented ones. A fixture
 * that spread a nested summary flat; a fixture that omitted a field the server always sends.
 * Both passed their suites, because a literal nobody checks is simply a different test passing.
 */
describe('the fixture checker', () => {
    it('accepts a fixture shaped as the document says', () => {
        const detail = asSchema('ScanDetail', {
            scan: { id: 34, status: 'completed', branch: 'master', attempts: 1, findingsCount: 0, newIssuesCount: 0, resolvedIssuesCount: 0 },
            hasSbom: false,
            findings: [],
            findingsTotal: 0,
            findingsTruncated: false
        });

        expect(detail.hasSbom).toBe(false);
    });

    /**
     * The scan detail bug, as a test. The screen read `detail.id`; the server nests the summary
     * under `scan`, and ten fields of the header rendered blank while the fixture agreed with the
     * screen.
     */
    it('refuses a fixture that spreads a nested shape flat', () => {
        expect(() =>
            asSchema('ScanDetail', {
                id: 34,
                status: 'completed',
                branch: 'master',
                hasSbom: false,
                findings: [],
                findingsTotal: 0,
                findingsTruncated: false
            })
        ).toThrow(/ScanDetail\.id: the fixture carries this, the document does not declare it/);
    });

    it('refuses a fixture that omits what the document marks always sent', () => {
        expect(() => asSchema('UserSummary', { username: 'c.moreau', role: 'USER' })).toThrow(
            /mustChangePassword: the document marks this always sent/
        );
    });

    it('refuses a scalar of the wrong type, at the path where it sits', () => {
        expect(() =>
            asSchema('TeamSummary', { id: 4, name: 7, memberCount: 0, targetCount: 0, notified: false })
        ).toThrow(/TeamSummary\.name: the document says string, the fixture holds number/);
    });

    /**
     * `null` passes everywhere, deliberately: the document marks nothing nullable while this
     * server sends `displayName: null`. Refusing it would reject fixtures that are exactly right.
     */
    it('accepts null wherever the server may send it', () => {
        const user = asSchema('UserSummary', {
            username: 'c.moreau',
            displayName: null,
            role: 'USER',
            mustChangePassword: false,
            mfaEnabled: false
        });

        expect(user.displayName).toBeNull();
    });

    it('checks each element of a list, and says which one', () => {
        expect(() => asSchemaList('TeamSummary', [{ id: 1, name: 'ok', memberCount: 0, targetCount: 0, notified: false }, { nom: 'oops' }])).toThrow(
            /nom: the fixture carries this/
        );
    });

    /** A fixture pointing at a schema nobody publishes is a fixture nobody can check. */
    it('refuses a schema name the document does not have', () => {
        // @ts-expect-error the name is not one of the document's schemas, and the type says so too
        expect(() => asSchema('NotAThing', {})).toThrow(/no schema called "NotAThing"/);
    });
});
