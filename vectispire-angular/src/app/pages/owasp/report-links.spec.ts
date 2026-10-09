import { describe, expect, it } from 'vitest';
import { issueLinker, Segment } from './report-links';

/** The text the reader sees, with each link marked as `[text→route]`. */
function render(segments: Segment[]): string {
    return segments
        .map((segment) =>
            segment.route
                ? `[${segment.text}→${segment.route.commands.join('/')}${
                      segment.route.queryParams ? '?' + new URLSearchParams(segment.route.queryParams).toString() : ''
                  }]`
                : segment.text
        )
        .join('');
}

describe('the identifiers of a report, as links', () => {
    const one = (issueId: number) => ({ issueId, count: 1 });

    it('links an identifier the server resolved to its issue, and leaves the rest as it was', () => {
        const link = issueLinker({ 'CVE-2026-1234': one(42) }, 5);
        const segments = link('Upgrade jackson for CVE-2026-1234 now.');
        expect(render(segments)).toBe('Upgrade jackson for [CVE-2026-1234→/issues/42] now.');
        // Nothing lost or added: the segments are the text.
        expect(segments.map((s) => s.text).join('')).toBe('Upgrade jackson for CVE-2026-1234 now.');
    });

    it('never links inside a longer token', () => {
        const link = issueLinker({ 'CVE-2026-1': one(1) }, 5);
        expect(render(link('CVE-2026-1000 and CVE-2026-10'))).toBe('CVE-2026-1000 and CVE-2026-10');
        // A separator followed by more of an identifier extends it: these are other identifiers.
        expect(render(link('CVE-2026-1-rc CVE-2026-1.2 CVE-2026-1:x CVE-2026-1/y CVE-2026-1_b'))).toBe(
            'CVE-2026-1-rc CVE-2026-1.2 CVE-2026-1:x CVE-2026-1/y CVE-2026-1_b'
        );
        expect(render(link('XCVE-2026-1 a-CVE-2026-1 a/CVE-2026-1'))).toBe('XCVE-2026-1 a-CVE-2026-1 a/CVE-2026-1');
    });

    it('still links an identifier closing a sentence, a clause or a parenthesis', () => {
        const link = issueLinker({ 'CVE-2026-1': one(1) }, 5);
        expect(render(link('See CVE-2026-1. Then (CVE-2026-1), CVE-2026-1: done'))).toBe(
            'See [CVE-2026-1→/issues/1]. Then ([CVE-2026-1→/issues/1]), [CVE-2026-1→/issues/1]: done'
        );
        expect(render(link('CVE-2026-1'))).toBe('[CVE-2026-1→/issues/1]');
    });

    it('prefers the longest identifier where one contains another', () => {
        const link = issueLinker({ 'java/sql-injection': one(1), 'java/sql-injection/tainted': one(2) }, 5);
        expect(render(link('Rule java/sql-injection/tainted then java/sql-injection.'))).toBe(
            'Rule [java/sql-injection/tainted→/issues/2] then [java/sql-injection→/issues/1].'
        );
        // Where the boundary alone cannot tell them apart — `@` ends neither — only the order does.
        const purl = issueLinker({ 'pkg:npm/lodash': one(3), 'pkg:npm/lodash@4.17.20': one(4) }, 5);
        expect(render(purl('pkg:npm/lodash@4.17.20 and pkg:npm/lodash'))).toBe(
            '[pkg:npm/lodash@4.17.20→/issues/4] and [pkg:npm/lodash→/issues/3]'
        );
    });

    it('matches identifiers literally, whatever characters they hold', () => {
        // Unescaped, the dot would match any character and `a.b` would link `axb`; `(` would not compile.
        const link = issueLinker({ 'a.b': one(1), 'rule(x)+': one(2), 'pkg:npm/lodash@4.17.20': one(3) }, 5);
        expect(render(link('axb a.b'))).toBe('axb [a.b→/issues/1]');
        expect(render(link('see rule(x)+ here'))).toBe('see [rule(x)+→/issues/2] here');
        expect(render(link('in pkg:npm/lodash@4.17.20, fix'))).toBe('in [pkg:npm/lodash@4.17.20→/issues/3], fix');
    });

    it('is case-sensitive: an identifier is matched as sent', () => {
        expect(render(issueLinker({ 'CVE-2026-1': one(1) }, 5)('cve-2026-1'))).toBe('cve-2026-1');
    });

    it('opens the repository backlog searched by the identifier when several issues carry it', () => {
        const link = issueLinker({ 'CVE-2026-7': { issueId: null, count: 3 } }, 5);
        expect(render(link('CVE-2026-7 again'))).toBe('[CVE-2026-7→/issues?repository_id=5&search=CVE-2026-7] again');
    });

    it('leaves as text an identifier that resolves to nothing it can open', () => {
        // No issue and not several — and a search link with no repository to narrow it would open
        // the whole estate's backlog.
        expect(render(issueLinker({ X: { issueId: null, count: 1 } }, 5)('X'))).toBe('X');
        expect(render(issueLinker({ X: { issueId: null, count: 0 } }, 5)('X'))).toBe('X');
        expect(render(issueLinker({ X: { issueId: null, count: 2 } }, null)('X'))).toBe('X');
    });

    it('links nothing that merely looks like an identifier', () => {
        // The prose is model output from third-party content: only what the server listed is a link.
        const link = issueLinker({ 'CVE-2026-1': one(1) }, 5);
        expect(render(link('CVE-2026-9999 GHSA-xxxx-yyyy-zzzz'))).toBe('CVE-2026-9999 GHSA-xxxx-yyyy-zzzz');
        expect(issueLinker({ 'CVE-2026-1': one(1) }, 5)('CVE-2026-9999').every((s) => s.route === null)).toBe(true);
    });

    it('returns the text whole for a report without links, and nothing for no text', () => {
        for (const links of [null, undefined, {}]) {
            const link = issueLinker(links, 5);
            expect(link('CVE-2026-1 stays text')).toEqual([{ text: 'CVE-2026-1 stays text', route: null }]);
            expect(link('')).toEqual([]);
            expect(link(null)).toEqual([]);
        }
        expect(issueLinker({ 'CVE-2026-1': one(1) }, 5)(undefined)).toEqual([]);
        // An empty identifier would match everywhere.
        expect(render(issueLinker({ '': one(1) }, 5)('abc'))).toBe('abc');
    });
});
