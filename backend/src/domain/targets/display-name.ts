/**
 * Le nom sous lequel une cible s'affiche — **une seule définition**.
 *
 * L'écran Dépôts abrégeait l'URL côté client tandis que le tableau de bord affichait
 * l'URL entière : le même dépôt portait deux noms selon la page, et rien ne dit à
 * l'utilisateur qu'il s'agit du même. Le nom appartient donc au serveur, qui le rend
 * identique à tous ses appelants.
 */

/** `org/projet` à partir d'une URL git, quelle qu'en soit la forme. */
export function shortRepositoryName(url: string): string {
    const withoutSuffix = url.replace(/\.git$/, '').replace(/\/+$/, '');
    const segments = withoutSuffix.split(/[/:]/).filter(Boolean);
    // Les deux derniers segments : `org/projet`, y compris sur une forme SCP
    // (`git@hote:equipe/sous-groupe/projet`) où le premier « : » n'est pas un port.
    return segments.slice(-2).join('/') || withoutSuffix;
}

/** Le nom choisi par l'opérateur s'il en a donné un, sinon la forme courte. */
export function repositoryDisplayName(repository: { name: string | null; url: string }): string {
    return repository.name?.trim() || shortRepositoryName(repository.url);
}

export function containerDisplayName(container: { imageName: string; tag: string }): string {
    // Sans abréger le condensé ici : ce nom sert aussi de clé de recherche et de libellé
    // d'export, où la valeur entière compte. L'abrègement est une affaire d'affichage.
    return `${container.imageName}:${container.tag}`;
}
