import { AuditEntryForHash, AuditEntryForVerification, computeEntryHash, rebuildChain, verifyChain } from './audit-hash';

describe('audit log entry hash', () => {
    describe('canonicalization', () => {
        const base: AuditEntryForHash = {
            previousHash: null,
            timestamp: new Date('2026-01-02T03:04:05.123Z'),
            operationType: 'LOGIN_SUCCESS',
            resourceId: 'alice',
            userId: 'alice',
            ipAddress: '10.0.0.4',
            userAgent: 'Mozilla/5.0',
            description: 'Successful login'
        };

        it('depends on the instant and not on how it was built', () => {
            // Two `Date`s built differently for the same instant: the canonical form is in
            // UTC, so the hash does not depend on the timezone of the machine computing
            // it. That is the property that matters for a control meant to be verifiable
            // somewhere other than where it was written.
            const sameInstant = new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 123));
            expect(computeEntryHash({ ...base, timestamp: sameInstant })).toBe(computeEntryHash(base));
        });

        it('tells two instants apart to the millisecond', () => {
            expect(computeEntryHash({ ...base, timestamp: new Date('2026-01-02T03:04:05.124Z') })).not.toBe(computeEntryHash(base));
        });

        it('tells a missing timestamp apart', () => {
            expect(computeEntryHash({ ...base, timestamp: null })).not.toBe(computeEntryHash(base));
        });
    });

    describe('sensitivity to content', () => {
        const base: AuditEntryForHash = {
            previousHash: null,
            timestamp: new Date('2026-08-10T08:13:58.322Z'),
            operationType: 'LOGIN_SUCCESS',
            resourceId: 'alice',
            userId: 'alice',
            ipAddress: '10.0.0.4',
            userAgent: 'Mozilla/5.0',
            description: 'Successful login'
        };

        it.each([['operationType'], ['resourceId'], ['userId'], ['ipAddress'], ['userAgent'], ['description'], ['previousHash'], ['timestamp']] as const)('changes when %s changes', (field) => {
            const altered: AuditEntryForHash = { ...base };
            // One millisecond apart, not one microsecond: the canonical form stops at the
            // millisecond, which the previous block checks in its own right.
            if (field === 'timestamp') altered.timestamp = new Date('2026-08-10T08:13:58.323Z');
            else (altered as unknown as Record<string, unknown>)[field] = 'altered';
            expect(computeEntryHash(altered)).not.toBe(computeEntryHash(base));
        });

        it('treats null and the empty string as equivalent', () => {
            expect(computeEntryHash({ ...base, userAgent: null })).toBe(computeEntryHash({ ...base, userAgent: '' }));
        });

        it('does not let content imitate a field boundary', () => {
            // The NUL separator exists for this: moving text from one field to the next
            // must change the hash.
            const a = computeEntryHash({ ...base, resourceId: 'ab', userId: 'cd' });
            const b = computeEntryHash({ ...base, resourceId: 'a', userId: 'bcd' });
            expect(a).not.toBe(b);
        });
    });
});

describe('chain verification', () => {
    function chained(count: number): AuditEntryForVerification[] {
        const entries: AuditEntryForVerification[] = [];
        let previousHash: string | null = null;
        for (let i = 0; i < count; i += 1) {
            const entry: AuditEntryForVerification = {
                id: `entry-${i}`,
                previousHash,
                timestamp: new Date(Date.UTC(2026, 7, 10, 8, 0, i)),
                operationType: 'SETTING_UPDATED',
                resourceId: String(i),
                userId: 'admin',
                ipAddress: null,
                userAgent: null,
                description: `Change ${i}`,
                entryHash: null
            };
            entry.entryHash = computeEntryHash(entry);
            previousHash = entry.entryHash;
            entries.push(entry);
        }
        return entries;
    }

    it('accepts an intact chain', () => {
        expect(verifyChain(chained(5))).toEqual({ broken: null, unverifiable: 0 });
    });

    it('accepts an empty chain', () => {
        expect(verifyChain([])).toEqual({ broken: null, unverifiable: 0 });
    });

    it('reports an entry whose content was modified after the fact', () => {
        const entries = chained(5);
        entries[2].description = 'Rewritten description';
        expect(verifyChain(entries).broken).toContain('entry-2');
        expect(verifyChain(entries).broken).toContain('no longer matches');
    });

    it('reports a deleted entry', () => {
        const entries = chained(5);
        entries.splice(2, 1);
        expect(verifyChain(entries).broken).toContain('entry-3');
        expect(verifyChain(entries).broken).toContain('deleted');
    });

    it('counts entries predating the chaining without refusing them', () => {
        // They carry no hash because they predate the feature, not because anyone touched
        // them.
        const entries = chained(3);
        const legacy: AuditEntryForVerification = { ...entries[0], id: 'legacy', entryHash: null, previousHash: null };
        expect(verifyChain([legacy, ...entries])).toEqual({ broken: null, unverifiable: 1 });
    });

    it('refuses an entry with no hash dated after the chaining started', () => {
        // **Dated, and not merely placed in the middle of the list.** Verification no
        // longer reads position — it stopped meaning anything once two instances writing
        // at the same instant produce legitimate branches. What tells a hand-placed row
        // from an inherited one is its date: the first is later than the start of the
        // chaining, the second is not.
        const entries = chained(3);
        const inserted = { ...entries[0], id: 'inserted', entryHash: null, timestamp: new Date(Date.UTC(2026, 7, 10, 8, 0, 1, 500)) };

        expect(verifyChain([...entries, inserted]).broken).toContain('inserted');
        expect(verifyChain([...entries, inserted]).broken).toContain('inserted or modified');
    });

    it('accepts two branches born of the same link', () => {
        // **What verification used to refuse wrongly.** Two web instances reading the same
        // tail at the same instant produce two entries carrying the same predecessor. The
        // log is perfectly honest; the old verification declared it broken, and a false
        // alarm in an integrity check ends up covering the real ones.
        const entries = chained(2);
        const twin: AuditEntryForVerification = {
            ...entries[1],
            id: 'concurrent',
            resourceId: 'other',
            description: 'Written at the same instant by another instance',
            entryHash: null
        };
        twin.entryHash = computeEntryHash(twin);

        expect(verifyChain([...entries, twin])).toEqual({ broken: null, unverifiable: 0 });
    });

    it('does not detect the deletion of a branch tip, and that is the accepted price', () => {
        // Nothing points at the last entry: nothing is missing once it is gone. Closing
        // that case would mean serializing every audit write, hence making each audited
        // action wait behind the others. Written here so the limit is a visible decision
        // rather than an oversight.
        const entries = chained(3);

        expect(verifyChain(entries.slice(0, 2)).broken).toBeNull();
    });
});

describe('chain rebuilding', () => {
    /**
     * Entries carrying hashes from another formula — consistent with each other and wrong
     * for this one. That is the situation of a log inherited from an earlier version: the
     * rebuild must make it verifiable without touching the content.
     */
    function foreignFormula(count: number): AuditEntryForVerification[] {
        return Array.from({ length: count }, (_, index) => ({
            id: `entry-${index}`,
            // Hashes from another formula: present, consistent with each other, and wrong
            // for this one.
            previousHash: index === 0 ? null : `legacy-${index - 1}`,
            entryHash: `legacy-${index}`,
            timestamp: new Date(Date.UTC(2026, 7, 10, 8, 0, index)),
            operationType: 'SETTING_UPDATED',
            resourceId: String(index),
            userId: 'admin',
            ipAddress: null,
            userAgent: null,
            description: `Change ${index}`
        }));
    }

    it('makes a history from the old formula verifiable', () => {
        const entries = foreignFormula(5);
        expect(verifyChain(entries).broken).not.toBeNull();

        rebuildChain(entries);

        expect(verifyChain(entries)).toEqual({ broken: null, unverifiable: 0 });
    });

    it('does not touch the entries content', () => {
        // Rewriting an integrity log is quite enough; rewriting its content would be
        // exactly what that log exists to make detectable.
        const entries = foreignFormula(3);
        const before = entries.map((entry) => ({ ...entry, previousHash: undefined, entryHash: undefined }));

        rebuildChain(entries);

        expect(entries.map((entry) => ({ ...entry, previousHash: undefined, entryHash: undefined }))).toEqual(before);
    });

    it('starts from scratch: the first entry has no predecessor', () => {
        const [first] = rebuildChain(foreignFormula(3));
        expect(first.previousHash).toBeNull();
    });

    it('is idempotent', () => {
        // Run again by mistake, it must produce exactly the same chain.
        const once = rebuildChain(foreignFormula(4)).map((entry) => entry.entryHash);
        const twice = rebuildChain(rebuildChain(foreignFormula(4))).map((entry) => entry.entryHash);
        expect(twice).toEqual(once);
    });
});
