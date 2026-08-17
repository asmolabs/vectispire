import { formatImageReference, validateImageReference } from './image-reference';

describe('référence d’image', () => {
    const ref = (imageName: string, tag = 'latest', registry: string | null = null) => ({ registry, imageName, tag });

    it.each([
        [ref('nginx')],
        [ref('library/nginx', '1.27-alpine')],
        [ref('equipe/service', 'v2.1.0', 'registry.interne:5000')],
        [ref('nginx', 'sha256:' + 'a'.repeat(64), 'ghcr.io')]
    ])('accepte %o', (value) => {
        expect(validateImageReference(value)).toBeNull();
    });

    it("refuse un nom en majuscules, que le registre refuserait au premier scan", () => {
        expect(validateImageReference(ref('Equipe/Service'))).toMatch(/Lower case/);
    });

    it('refuse une référence qui décalerait les arguments du conteneur', () => {
        expect(validateImageReference(ref('nginx --privileged'))).not.toBeNull();
        expect(validateImageReference(ref('nginx', 'latest ; rm -rf /'))).not.toBeNull();
    });

    it.each([[ref('')], [ref('nginx', '')], [ref('nginx', 'latest', 'pas un hôte/du tout')]])('refuse %o', (value) => {
        expect(validateImageReference(value)).not.toBeNull();
    });

    it('colle un condensé avec « @ » et une étiquette avec « : »', () => {
        const digest = 'sha256:' + 'b'.repeat(64);
        expect(formatImageReference(ref('nginx', digest, 'ghcr.io'))).toBe(`ghcr.io/nginx@${digest}`);
        expect(formatImageReference(ref('nginx', '1.27'))).toBe('nginx:1.27');
    });
});
