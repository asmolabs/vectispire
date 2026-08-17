import { agentAccepts, normalizeRequiredLabel, parseAgentLabels } from './targeting';

describe("ciblage d'un scan vers un agent", () => {
    describe('labels announced by an agent', () => {
        it('splits, trims and lowers the case', () => {
            // "Production" and "production", typed six months apart on two screens, must
            // mean the same thing: otherwise a scan waits indefinitely for an agent that is
            // right there, and nothing on screen explains why.
            expect(parseAgentLabels(' Production , customer-network ')).toEqual(['production', 'customer-network']);
        });

        it('returns no label for an agent that declares none', () => {
            expect(parseAgentLabels(null)).toEqual([]);
            expect(parseAgentLabels('')).toEqual([]);
            // Commas alone are not labels: without this filter, the string
            // vide entrerait dans la liste et satisferait une exigence vide.
            expect(parseAgentLabels(' , , ')).toEqual([]);
        });

        it('does not count the same label twice', () => {
            expect(parseAgentLabels('prod,PROD, prod ')).toEqual(['prod']);
        });
    });

    describe("the requirement a target carries", () => {
        it('normalizes like the labels, so the comparison means something', () => {
            expect(normalizeRequiredLabel('  Customer-Network ')).toBe('customer-network');
        });

        it('treats a cleared field as no requirement any more', () => {
            // **The case that would silently jam a queue.** Storing the empty string would give
            // une exigence qu'aucun agent ne satisfait jamais, et le scan attendrait sans
            // que rien ne le dise.
            expect(normalizeRequiredLabel('')).toBeNull();
            expect(normalizeRequiredLabel('   ')).toBeNull();
            expect(normalizeRequiredLabel(null)).toBeNull();
        });
    });

    describe('the decision', () => {
        it('leaves a scan with no requirement to whoever asks', () => {
            // The previous behaviour. Requiring a label retroactively would stop every
            // existing queue on the first deployment.
            expect(agentAccepts([], null)).toBe(true);
            expect(agentAccepts(['prod'], null)).toBe(true);
        });

        it('reserves a demanding scan for the agent carrying the label', () => {
            expect(agentAccepts(['prod', 'client'], 'client')).toBe(true);
            expect(agentAccepts(['prod'], 'client')).toBe(false);
        });

        it('does not let an agent with no label match everything', () => {
            // **Closed by default on the agent's side.** The reverse — "no label means all
            // of them" — is the seductive reading, and it would make the requirement
            // inoperative at the first agent registered without thinking about it.
            expect(agentAccepts([], 'client')).toBe(false);
        });
    });
});
