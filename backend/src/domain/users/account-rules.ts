import { ADMIN_ROLES, VALID_ROLES } from './roles';

/**
 * Les règles qui empêchent un administrateur de se verrouiller dehors.
 *
 * Elles vivent ici, pures, parce que ce sont des règles et non des requêtes : chacune
 * décrit une situation où l'interface accepterait volontiers une action dont personne ne
 * pourrait revenir. Il n'existe pas d'écran de secours dans Zanshin — plus aucun
 * administrateur actif, et il faut une session psql.
 */

export const MINIMUM_PASSWORD_LENGTH = 12;

const USERNAME = /^[A-Za-z0-9._-]{2,64}$/;

export function isAdminRole(role: string): boolean {
    return (ADMIN_ROLES as readonly string[]).includes(role);
}

/** `null` si le nom est acceptable, sinon le message à montrer. */
export function validateUsername(username: string): string | null {
    if (!username) return "L'identifiant est requis.";
    if (!USERNAME.test(username)) {
        return "Identifiant invalide : 2 à 64 caractères, lettres, chiffres, « . _ - ».";
    }
    return null;
}

/**
 * `null` si le mot de passe est acceptable.
 *
 * Une longueur minimale et rien d'autre — pas de règle de composition. Les exigences de
 * classes de caractères produisent `Motdepasse1!` et poussent à la réutilisation ; la
 * longueur est la seule contrainte dont l'effet sur l'entropie soit réel.
 */
export function validatePassword(password: string): string | null {
    if (!password) return 'Le mot de passe est requis.';
    if (password.length < MINIMUM_PASSWORD_LENGTH) {
        return `Le mot de passe doit faire au moins ${MINIMUM_PASSWORD_LENGTH} caractères.`;
    }
    // bcrypt tronque à 72 octets : au-delà, les caractères supplémentaires ne
    // protègent rien, et le laisser croire serait pire que de le refuser.
    if (Buffer.byteLength(password, 'utf8') > 72) {
        return 'Le mot de passe dépasse 72 octets, au-delà desquels bcrypt ignore la suite.';
    }
    return null;
}

export function validateRole(role: string): string | null {
    return (VALID_ROLES as readonly string[]).includes(role)
        ? null
        : `Rôle « ${role} » inconnu. Attendu ${VALID_ROLES.join(', ')}.`;
}

/**
 * `null` si la modification est permise, sinon pourquoi elle est refusée.
 *
 * `remainingActiveAdmins` compte les administrateurs actifs **autres que celui-ci**.
 * Refuser au niveau du compte plutôt qu'à celui de l'écran : trois onglets ouverts sur
 * deux comptes suffiraient sinon à vider la liste des administrateurs.
 */
export function refuseSelfLockout(options: {
    isSelf: boolean;
    wasAdmin: boolean;
    willBeAdmin: boolean;
    willBeActive: boolean;
    remainingActiveAdmins: number;
}): string | null {
    const { isSelf, wasAdmin, willBeAdmin, willBeActive, remainingActiveAdmins } = options;

    if (isSelf && !willBeActive) return 'Vous ne pouvez pas désactiver votre propre compte.';
    if (isSelf && wasAdmin && !willBeAdmin) return 'Vous ne pouvez pas retirer votre propre rôle administrateur.';

    const losesAdmin = wasAdmin && (!willBeAdmin || !willBeActive);
    if (losesAdmin && remainingActiveAdmins === 0) {
        return "C'est le dernier administrateur actif : le retirer laisserait Zanshin sans personne pour administrer.";
    }
    return null;
}

/** Idem pour la suppression, dont les conséquences sont les mêmes en pire. */
export function refuseDeletion(options: { isSelf: boolean; isAdmin: boolean; remainingActiveAdmins: number }): string | null {
    if (options.isSelf) return 'Vous ne pouvez pas supprimer votre propre compte.';
    if (options.isAdmin && options.remainingActiveAdmins === 0) {
        return "C'est le dernier administrateur actif : le supprimer laisserait Zanshin sans personne pour administrer.";
    }
    return null;
}
