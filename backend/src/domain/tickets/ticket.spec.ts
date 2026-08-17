import { type TicketableIssue, buildBody, buildTitle, parseLabels, parseProvider } from './ticket';

function issue(values: Partial<TicketableIssue> = {}): TicketableIssue {
    return {
        id: 12,
        type: 'vulnerability',
        identifier: 'CVE-2021-44228',
        severity: 'critical',
        packageName: 'log4j-core',
        packageVersion: '2.14.1',
        fixVersions: null,
        fixState: null,
        isDirectDependency: null,
        filePath: null,
        line: null,
        isKev: false,
        epssScore: null,
        link: null,
        description: null,
        fingerprint: 'abc123',
        ...values
    };
}

describe('buildTitle', () => {
    it('stays short and searchable', () => {
        expect(buildTitle(issue(), 'org/projet')).toBe('[Zanshin][CRITICAL] CVE-2021-44228 — log4j-core (org/projet)');
    });

    it('retombe sur le type quand il n\'y a pas d\'identifiant', () => {
        expect(buildTitle(issue({ identifier: null, type: 'secret', packageName: null, severity: null }), 'org/projet')).toBe(
            '[Zanshin][UNKNOWN] secret (org/projet)'
        );
    });
});

describe('buildBody', () => {
    it('puts the fixed version first among the details', () => {
        // It is what makes the difference between a ticket closed today and a ticket
        // dragged across three iterations.
        const body = buildBody(issue({ fixVersions: '2.17.1' }), 'org/projet');

        expect(body).toContain('**Fixed in: 2.17.1**');
        expect(body.indexOf('Fixed in')).toBeLessThan(body.indexOf('Component'));
    });

    it('says explicitly that no fix exists', () => {
        // Silence would read as "we did not look", when this is information: there is
        // nothing to upgrade to, and mitigation has to come from somewhere else.
        expect(buildBody(issue({ fixState: 'not-fixed' }), 'org/projet')).toContain('No published fix');
    });

    it('reports active exploitation and the EPSS score', () => {
        const body = buildBody(issue({ isKev: true, epssScore: 0.97512 }), 'org/projet');

        expect(body).toContain('Known active exploitation');
        expect(body).toContain('97.5%');
    });

    it('tells a direct dependency from a transitive one', () => {
        expect(buildBody(issue({ isDirectDependency: true }), 'org/projet')).toContain('direct (declared by the project)');
        expect(buildBody(issue({ isDirectDependency: false }), 'org/projet')).toContain('transitive');
        // `null` veut dire « on ne sait pas » : ne rien dire vaut mieux que deviner.
        expect(buildBody(issue(), 'org/projet')).not.toContain('Dependency:');
    });

    it('tronque une description bavarde', () => {
        // A ticket you have to scroll through to find the conclusion does not get read.
        const body = buildBody(issue({ description: 'x'.repeat(5000) }), 'org/projet');

        expect(body).toContain('x'.repeat(1000));
        expect(body).not.toContain('x'.repeat(1001));
    });

    it('carries the fingerprint and the reason it was opened', () => {
        // The fingerprint makes the issue findable from the ticket; the reason heads off
        // the question "why this one and not that one".
        const body = buildBody(issue(), 'org/projet');

        expect(body).toContain('fingerprint `abc123`');
        expect(body).toContain('would fail a build');
    });
});

describe('parseLabels', () => {
    it('splits and cleans', () => {
        expect(parseLabels('zanshin, security ,')).toEqual(['zanshin', 'security']);
        expect(parseLabels('')).toEqual([]);
    });
});

describe('parseProvider', () => {
    it('normalise et refuse ce qui sort du vocabulaire', () => {
        expect(parseProvider('  GitLab ')).toBe('gitlab');
        expect(parseProvider('github')).toBe('none');
        expect(parseProvider('')).toBe('none');
    });
});
