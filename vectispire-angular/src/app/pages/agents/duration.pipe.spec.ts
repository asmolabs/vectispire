import { describe, expect, it } from 'vitest';
import { DurationPipe, formatDuration } from './duration.pipe';

/** A duration in seconds as the agents screen writes it: minutes and seconds, `0s` for nothing. */
describe('the duration pipe', () => {
    it('writes seconds alone under a minute, and minutes and seconds past it', () => {
        expect(formatDuration(12)).toBe('12s');
        expect(formatDuration(75)).toBe('1m 15s');
        expect(formatDuration(120)).toBe('2m 0s');
    });

    it('writes 0s for nothing and for a negative figure', () => {
        expect(formatDuration(0)).toBe('0s');
        expect(formatDuration(-5)).toBe('0s');
    });

    it('is the same function as a pipe', () => {
        expect(new DurationPipe().transform(61)).toBe('1m 1s');
    });
});
