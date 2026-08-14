import { DependencyDirectness } from './directness';

/** Un SBOM minimal : `lib-a` est déclarée, `lib-b` est tirée par elle. */
const SBOM = {
    artifacts: [
        { id: 'a1', name: 'lib-a', version: '1.0', purl: 'pkg:npm/lib-a@1.0' },
        { id: 'b1', name: 'lib-b', version: '2.0', purl: 'pkg:npm/lib-b@2.0' }
    ],
    artifactRelationships: [{ type: 'dependency-of', parent: 'b1', child: 'a1' }]
};

describe('DependencyDirectness', () => {
    it('distingue une racine du graphe de ce qui est tiré par autre chose', () => {
        const graph = new DependencyDirectness(SBOM);

        expect(graph.of('pkg:npm/lib-a@1.0')).toBe(true);
        expect(graph.of('pkg:npm/lib-b@2.0')).toBe(false);
    });

    it("rend tout inconnu quand le SBOM ne porte aucune arête", () => {
        // Le point important : sans arêtes, *tout* paquet ressemble à une racine, ce qui
        // étiquetterait une image entière « dépendances directes ». Une réponse fausse et
        // assurée sur le champ qui décide quoi corriger en premier est pire que le silence.
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
        // Deux versions d'un même paquet peuvent tomber de part et d'autre : l'une
        // déclarée, l'autre traînée par une dépendance.
        const graph = new DependencyDirectness({
            artifacts: [{ id: 'a1', name: 'lib', version: '1.0' }, { id: 'a2', name: 'lib', version: '2.0' }],
            artifactRelationships: [{ type: 'dependency-of', parent: 'a2', child: 'a1' }]
        });

        expect(graph.of(null, 'lib', '1.0')).toBe(true);
        expect(graph.of(null, 'lib', '2.0')).toBe(false);
        // Sans version, aucune réponse plutôt qu'un tirage au sort.
        expect(graph.of(null, 'lib')).toBeNull();
    });

    it('rend inconnu pour un paquet absent du SBOM', () => {
        expect(new DependencyDirectness(SBOM).of('pkg:npm/inconnu@9.9')).toBeNull();
    });
});
