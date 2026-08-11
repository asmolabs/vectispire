/**
 * Validation d'une référence d'image de conteneur.
 *
 * Même nature que `git-url.ts` : la référence est passée à un scanner qui la tire depuis
 * un registre. Une valeur non contrôlée y fait tirer une image arbitraire — ou, si elle
 * contient un espace, décale les arguments de la ligne de commande du conteneur.
 *
 * La grammaire d'OCI est plus permissive que ce qui suit ; on refuse ici tout ce qui
 * n'est pas manifestement une image, quitte à écarter des formes exotiques légitimes.
 * Le coût d'un refus est un message ; le coût d'une acceptation de trop ne l'est pas.
 */

const REGISTRY = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?$/;
const IMAGE_NAME = /^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*$/;
const TAG = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

export interface ImageReference {
    registry: string | null;
    imageName: string;
    tag: string;
}

/** `null` si la référence est acceptable, sinon le message à montrer. */
export function validateImageReference(reference: ImageReference): string | null {
    const { registry, imageName, tag } = reference;

    if (registry !== null && registry !== '' && !REGISTRY.test(registry)) {
        return `Registre « ${registry} » invalide. Attendu un hôte, éventuellement suivi de « :port ».`;
    }
    if (!imageName) return "Le nom de l'image est requis.";
    if (!IMAGE_NAME.test(imageName)) {
        // Les majuscules sont refusées par le registre lui-même, pas par nous : autant le
        // dire à la saisie plutôt qu'au premier scan.
        return `Nom d'image « ${imageName} » invalide. Minuscules, chiffres, « . _ - » et « / ».`;
    }
    if (!tag) return "L'étiquette est requise (« latest » à défaut).";
    if (!TAG.test(tag) && !DIGEST.test(tag)) {
        return `Étiquette « ${tag} » invalide. Attendu une étiquette ou un condensé « sha256:… ».`;
    }
    return null;
}

/** La référence telle qu'un registre l'attend — ce qu'on affiche et ce qu'on scanne. */
export function formatImageReference(reference: ImageReference): string {
    const base = reference.registry ? `${reference.registry}/${reference.imageName}` : reference.imageName;
    // Un condensé se colle avec « @ », une étiquette avec « : ». Se tromper ici produit
    // une référence que le registre rejette.
    return reference.tag.startsWith('sha256:') ? `${base}@${reference.tag}` : `${base}:${reference.tag}`;
}
