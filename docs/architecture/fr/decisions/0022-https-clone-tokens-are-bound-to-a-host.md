# 0022 — Le clonage HTTPS utilise un jeton géré, lié à un hôte

**Date :** 2026-09-25 · **Statut :** acceptée · **Décideur :** Laurent Boucher

## Contexte

Vectispire clone en SSH avec des clés de déploiement gérées, et en HTTPS sans identifiant. Un dépôt
privé joignable seulement en HTTPS — le cas courant derrière un proxy d'entreprise, ou sur une forge
qui délivre des jetons d'accès personnels ou de projet plutôt que des clés — n'avait qu'une entrée :
le jeton écrit dans l'URL, `https://user:jeton@hôte/projet.git`.

Cela fonctionne, et c'est le mauvais endroit pour un secret. L'URL est conservée **en clair** dans
`t_repository.url`, à côté de lignes dont les autres secrets sont chiffrés ; elle doit être masquée
sur chaque écran, message et ligne d'audit (`RepositoryUrl.redact` n'existe que pour cela) ; et elle
part vers l'agent qui réclame l'analyse, quoi que promette son mode d'identifiants.

## Décision

**Un jeton HTTPS est un identifiant géré, comme une clé de déploiement, et il est lié à un hôte.**

- Un nouveau stockage, `t_git_token` : un nom, l'**hôte** pour lequel il est émis, un nom
  d'utilisateur facultatif, et le jeton chiffré avec la ligne pour contexte (`SecretCipher`), si bien
  qu'un chiffré recopié dans une autre ligne ne se déchiffre pas. Aucune route ne renvoie le jeton.
- Un dépôt référence soit une clé SSH, soit un jeton HTTPS, jamais les deux, et la référence doit
  correspondre à l'URL : un jeton seulement pour une URL `https://` **sur l'hôte du jeton**, une clé
  seulement pour SSH.
- **Le jeton n'est présenté qu'à son hôte.** Le clonage le fournit par un fournisseur d'identifiants
  qui ne répond que pour cet hôte : une redirection vers un autre hôte — ou une URL de dépôt que
  quelqu'un fait pointer ailleurs — ne reçoit aucun identifiant. Sans ce lien, rattacher un jeton de
  forge à un dépôt dont l'URL nomme un autre serveur y enverrait le jeton.
- Il rejoint l'analyse comme une clé de déploiement : déchiffré par le plan de contrôle, remis
  seulement à un exécutant en mode `delegated`, scellé pour la clé annoncée par l'agent, et refusé
  par un agent qui a annoncé une clé de scellement s'il arrive en clair. Un agent `local` ne reçoit
  aucun jeton, comme il ne reçoit aucune clé.
- **Les nouveaux identifiants dans une URL sont refusés** à la saisie, avec un message qui renvoie à
  l'écran des jetons. Les URL existantes continuent de fonctionner — les refuser à la mise à jour
  arrêterait ces analyses sans un mot — et restent masquées comme avant.

## Conséquences

- Un stockage chiffré de plus, un écran de plus, un champ de plus sur le formulaire du dépôt.
- Le protocole de l'agent gagne un champ facultatif sur la cible dépôt. Un agent antérieur l'ignore
  et clone sans identifiant, ce qui échoue avec « requires authentication » — visible, et corrigé en
  mettant l'agent à jour.
- Un agent `local` ne peut pas cloner un dépôt privé en HTTPS : JGit ne lit pas les assistants
  d'identifiants de git, et la configuration de l'hôte n'est que SSH aujourd'hui. C'est la promesse
  que le mode fait déjà pour les clés, et elle est dite plutôt que contournée.
- Faire tourner un jeton, c'est le remplacer : l'ancienne ligne est supprimée une fois qu'aucun dépôt
  ne l'utilise, comme une clé.
