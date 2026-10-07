import { describe, expect, it } from 'vitest';
import { readScope, scopeOfValue, scopeParams, scopeQuery, scopeValue } from './owasp-scope';

const url = (query: string) => new URLSearchParams(query);

/** The scope both OWASP views read from their URL and write into every link they make. */
describe('the OWASP scope', () => {
    it('reads a project or a solution, the narrower when a link carries both, and drops a garbled id', () => {
        expect(readScope(url('project_id=12'))).toEqual({ kind: 'project', id: 12 });
        expect(readScope(url('solution_id=3'))).toEqual({ kind: 'solution', id: 3 });
        // The server refuses both with a 400; the project is inside the solution, so it wins.
        expect(readScope(url('solution_id=3&project_id=12'))).toEqual({ kind: 'project', id: 12 });
        expect(readScope(url('project_id=abc'))).toBeNull();
        expect(readScope(url('project_id=0&solution_id=-1'))).toBeNull();
        expect(readScope(url(''))).toBeNull();
    });

    it('writes the same parameters back, and nothing for the estate', () => {
        expect(scopeParams({ kind: 'project', id: 12 })).toEqual({ project_id: '12' });
        expect(scopeParams(null)).toEqual({});
        expect(scopeQuery({ kind: 'solution', id: 3 })).toEqual({ solution_id: 3 });
        expect(scopeQuery(null)).toEqual({});
    });

    it('round-trips through the picker value, and reads an unknown value as the estate', () => {
        for (const scope of [{ kind: 'project', id: 12 } as const, { kind: 'solution', id: 3 } as const, null]) {
            expect(scopeOfValue(scopeValue(scope))).toEqual(scope);
        }
        expect(scopeOfValue('repository:5')).toBeNull();
        expect(scopeOfValue('project:x')).toBeNull();
        expect(scopeOfValue(null)).toBeNull();
    });
});
