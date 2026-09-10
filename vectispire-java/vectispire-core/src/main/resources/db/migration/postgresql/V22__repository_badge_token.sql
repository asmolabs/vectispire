-- Le jeton qui publie le badge d'un dépôt, et l'identifiant séquentiel qui ne le publiait plus.
--
-- **La route du badge servait la note de sécurité de n'importe quel dépôt, sans authentification,
-- indexée par un `Long` séquentiel.** `GET /api/v1/scorecards/repositories/{repoId}/badge.svg`
-- portait `@OpenToAnonymous` et n'appelait aucun `Visibility` : parcourir 1..N rendait la posture
-- de tout le parc, comptes et équipes confondus. Et comme un dépôt absent répondait `unknown` là
-- où un dépôt présent répondait une note, la route était en prime un oracle d'existence — ce que
-- `Visibilities.requireVisible` interdit explicitement partout ailleurs, en répondant 404 et
-- jamais 403.
--
-- **Un badge public reste une fonctionnalité légitime** : c'est une image dans un README, donc
-- lue par un navigateur qui n'a pas de session. Ce qui manquait n'est pas l'authentification,
-- c'est que la publication soit un acte.
--
-- D'où cette colonne. `null` — la valeur de toutes les lignes existantes, et celle d'un dépôt
-- créé demain — signifie « aucun badge n'est publié pour ce dépôt », et la route répond 404. Un
-- jeton signifie que quelqu'un l'a décidé, sur cette ligne, et l'entrée d'audit dit qui. Le jeton
-- est aléatoire et opaque : il ne se devine pas, il ne s'énumère pas, et le révoquer est un
-- `update` qui casse le lien sans toucher au dépôt.
--
-- Unique, parce que c'est par lui que la route retrouve la ligne : deux dépôts partageant un
-- jeton rendraient la réponse dépendante de l'ordre de tri.

alter table t_repository add column badge_token varchar(64);

create unique index idx_repository_badge_token on t_repository (badge_token);
