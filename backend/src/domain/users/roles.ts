/**
 * Le vocabulaire des rôles.
 *
 * Il vit dans le domaine et non dans l'entité : c'est une règle métier, pas une colonne.
 * `user.entity.ts` le réexporte pour ne pas casser les appelants, mais la définition est
 * ici — la règle de couches interdit à `domain/` de connaître `persistence/`, et elle a
 * raison : les rôles existeraient encore si Zanshin changeait de base.
 */
export const ADMIN_ROLES = ['SUPERUSER', 'ADMIN'] as const;
export const VALID_ROLES = ['SUPERUSER', 'ADMIN', 'USER'] as const;
