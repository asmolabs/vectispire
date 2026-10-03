import { describe, expect, it } from 'vitest';
import { keyFor } from './literal-keys';

describe('the key a value is spelt by', () => {
    const KEYS = { open: 'issues.states.open', resolved: 'issues.states.resolved' } as const;

    it('is the literal the map holds for a known value', () => {
        expect(keyFor(KEYS, 'open')).toBe('issues.states.open');
    });

    it('is nothing for a value the client does not know, so no key is ever built from it', () => {
        expect(keyFor(KEYS, 'reopened')).toBeUndefined();
        expect(keyFor(KEYS, null)).toBeUndefined();
        expect(keyFor(KEYS, undefined)).toBeUndefined();
        // Inherited names are not entries: `in` would answer true and index `Object.prototype`.
        expect(keyFor(KEYS, 'constructor')).toBeUndefined();
        expect(keyFor(KEYS, 'toString')).toBeUndefined();
    });
});
