import { DependencyDirectness } from './directness';

/** A minimal SBOM: `lib-a` is declared, `lib-b` is pulled in by it. */
const SBOM = {
    artifacts: [
        { id: 'a1', name: 'lib-a', version: '1.0', purl: 'pkg:npm/lib-a@1.0' },
        { id: 'b1', name: 'lib-b', version: '2.0', purl: 'pkg:npm/lib-b@2.0' }
    ],
    artifactRelationships: [{ type: 'dependency-of', parent: 'b1', child: 'a1' }]
};

describe('DependencyDirectness', () => {
    it('tells a root of the graph from what something else pulls in', () => {
        const graph = new DependencyDirectness(SBOM);

        expect(graph.of('pkg:npm/lib-a@1.0')).toBe(true);
        expect(graph.of('pkg:npm/lib-b@2.0')).toBe(false);
    });

    it("returns unknown for everything when the SBOM carries no edge", () => {
        // The important part: with no edges, *every* package looks like a root, which
        // would label a whole image "direct dependencies". A confident wrong answer on the
        // field that decides what to fix first is worse than silence.
        const graph = new DependencyDirectness({ artifacts: SBOM.artifacts });

        expect(graph.available).toBe(false);
        expect(graph.of('pkg:npm/lib-a@1.0')).toBeNull();
        expect(graph.of('pkg:npm/lib-b@2.0')).toBeNull();
    });

    it('rend inconnu sur un SBOM absent ou vide', () => {
        expect(new DependencyDirectness(null).of('pkg:npm/x@1')).toBeNull();
        expect(new DependencyDirectness({ artifacts: [] }).of('pkg:npm/x@1')).toBeNull();
    });

    it('retombe sur nom+version quand le catalogueur n\'a pas produit de purl', () => {
        const graph = new DependencyDirectness({
            artifacts: [{ id: 'a1', name: 'lib-a', version: '1.0' }, { id: 'b1', name: 'lib-b', version: '2.0' }],
            artifactRelationships: [{ type: 'dependency-of', parent: 'b1', child: 'a1' }]
        });

        expect(graph.of(null, 'lib-a', '1.0')).toBe(true);
        expect(graph.of(null, 'lib-b', '2.0')).toBe(false);
    });

    it("n'apparie jamais sur le nom seul", () => {
        // Two versions of the same package can fall on either side: one declared, the
        // other dragged in by a dependency.
        const graph = new DependencyDirectness({
            artifacts: [{ id: 'a1', name: 'lib', version: '1.0' }, { id: 'a2', name: 'lib', version: '2.0' }],
            artifactRelationships: [{ type: 'dependency-of', parent: 'a2', child: 'a1' }]
        });

        expect(graph.of(null, 'lib', '1.0')).toBe(true);
        expect(graph.of(null, 'lib', '2.0')).toBe(false);
        // With no version, no answer rather than a coin toss.
        expect(graph.of(null, 'lib')).toBeNull();
    });

    it('rend inconnu pour un paquet absent du SBOM', () => {
        expect(new DependencyDirectness(SBOM).of('pkg:npm/inconnu@9.9')).toBeNull();
    });
});
