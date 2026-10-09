# Note d'incident : identifiants commités dans une base de développement (août 2026)

*Rédigée en octobre 2026 à partir des traces du projet d'août 2026. Elle remplace une note de travail
antérieure qui listait les actions de suivi.*

## Ce qui a été exposé

Un fichier de base de données SQLite de développement a été commité dans le dépôt antérieur du
projet, qui était privé, et est resté dans son historique pendant plusieurs mois. Il contenait :

- les empreintes de mots de passe (bcrypt) des comptes locaux ;
- une clé SSH privée de déploiement, conservée « chiffrée » — mais avec une **clé de chiffrement par
  défaut qui était elle-même une constante du code source**, si bien que quiconque détenait le
  fichier pouvait la déchiffrer.

Les réglages conservés dans le même fichier auraient pu contenir un webhook de notification ou un
jeton de tracker ; aucun n'était renseigné lors de la vérification d'août 2026, et tout réglage
renseigné avant figurait aussi dans le fichier. Les clés d'agent sont apparues après l'exposition et
n'y ont jamais figuré.

## Quand et comment

- Le fichier a été commité au fil du développement, quand SQLite était la seule base possible.
- La façon dont il a été remarqué n'est pas consignée. Il a été retiré le **6 août 2026** — le jour où
  la couche de données est devenue configurable au-delà de SQLite — en réécrivant l'historique puis
  en le force-pushant.
- Un force-push ne supprime pas les objets sur la forge : les commits antérieurs à la réécriture
  restent accessibles par leur empreinte jusqu'à ce que la forge les purge. L'exposition était donc
  bornée par qui avait accès à ce dépôt privé, non close par la réécriture.

## Ce qui a été fait

- **Les identifiants exposés ont été déclarés compromis**, et la suite fixée : révoquer la clé de
  déploiement sur sa forge et la remplacer, imposer un changement de mot de passe aux comptes locaux,
  et faire tourner tout réglage qui portait un identifiant. La révocation chez le fournisseur est
  l'étape qui compte ; une purge sur la forge ferme une porte, une rotation invalide ce qui est passé
  par elle. Ces étapes ont lieu hors du dépôt, et leur achèvement n'y est pas consigné.
- **L'historique a été réécrit** (6 août 2026) et une purge côté serveur des objets non référencés
  de l'ancien dépôt a été demandée à la forge.
- **Le dépôt actuel est un nouveau dépôt**, créé le 27 août 2026, et non un renommage de l'ancien.
  Vérifié le 30 août 2026 : aucun des anciens commits n'y est présent, aucun objet de son historique
  ne correspond à un fichier de base ou de clé, et un scan gitleaks sur tout son historique n'a rien
  trouvé.

## Ce qui a changé dans le projet

- **La clé de chiffrement par défaut a disparu.** L'application ne porte plus de clé qui ouvre sa
  propre base : sans `ENCRYPTION_KEY` (ou Vault Transit), elle refuse de stocker un nouveau secret
  plutôt que de le chiffrer avec une valeur connue, et l'ancienne constante n'est pas essayée au
  déchiffrement. Une valeur chiffrée avec elle se lit *illisible* jusqu'à son remplacement. La
  rotation de la clé elle-même est décrite dans [`KEY_ROTATION.fr.md`](../../fr/KEY_ROTATION.fr.md).
- **Un fichier de base ne peut plus être commité par mégarde** : `*.db` et `*.sqlite*` sont ignorés,
  et la base est un serveur (MySQL ou PostgreSQL) configuré par l'environnement.
- **Le mot de passe d'amorçage est provisoire** : le compte qu'il crée doit le changer à la première
  connexion.
- **Chaque push et chaque pull request passe gitleaks sur tout l'historique** (le job `secrets` de
  `.github/workflows/ci.yml`, `fetch-depth: 0`). Les constats connus et jugés inoffensifs sont
  épinglés un par un dans `.gitleaksignore` plutôt qu'admis par motif. Ce job n'a lu aucun commit du
  25 août au 3 octobre 2026 tout en se déclarant réussi — git refusait la propriété du checkout dans
  le conteneur — et fait désormais échouer un scan qui n'a rien lu ou a journalisé une erreur.

## Ce qui reste vrai

- Ce qui a été cloné depuis l'ancien dépôt avant la réécriture ne peut pas être rappelé. Seule la
  rotation le rend sans valeur.
- L'achèvement de la purge de l'ancien dépôt par la forge n'est pas consigné ici ; il ne concerne que
  l'ancien dépôt, dont l'actuel ne descend pas.
- Une règle d'exclusion ou un scanner réduisent le risque de récidive ; aucun ne rend sûr un secret
  commité. Un secret arrivé dans un dépôt se révoque, il ne se nettoie pas.
