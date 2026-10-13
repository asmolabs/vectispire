import { describe, expect, it } from 'vitest';
import { SEVERITIES, SEVERITY_TONES, severityTone } from './severity';

/**
 * One colour scale for severities. Eight screens had their own, and `high` was red on five of them,
 * orange on three: the same finding changed colour between the dashboard and the backlog.
 */
describe('severityTone', () => {
    it('gives each of the four levels its own colour, and never the colour of good news', () => {
        expect(SEVERITIES.map((severity) => severityTone(severity))).toEqual([
            'danger',
            'warn',
            'info',
            'secondary',
            'secondary',
            'secondary'
        ]);
        // Critical and high apart: the dashboard's legend tells them apart, and so does triage.
        expect(severityTone('critical')).not.toBe(severityTone('high'));
        expect(Object.values(SEVERITY_TONES)).not.toContain('success');
    });

    it('reads the Java constant and the scanner case as the same severity', () => {
        expect(severityTone('HIGH')).toBe('warn');
        expect(severityTone('Critical')).toBe('danger');
    });

    it('paints a severity it does not know, or none, as neutral', () => {
        expect(severityTone('catastrophic')).toBe('secondary');
        expect(severityTone(null)).toBe('secondary');
        expect(severityTone(undefined)).toBe('secondary');
        // Not read off the prototype: `constructor` is not a severity.
        expect(severityTone('constructor')).toBe('secondary');
    });
});
