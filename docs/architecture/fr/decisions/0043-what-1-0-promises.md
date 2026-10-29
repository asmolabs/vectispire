# 0043 — Ce que promet 1.0 : une API additive, des agents d'une version en retard, un moteur, une instance, une ligne maintenue

**Date :** 2026-10-12 · **Amendée :** 2026-10-29 (§3 : MySQL seul) · **Statut :** proposée · **S'appuie sur :** [0003](0003-long-polling-for-agents.md), [0034](0034-mysql-replaces-the-sqlite-fixture.md), [0035](0035-report-plugins.md), [0038](0038-deploying-on-kubernetes.md) · **Décideur :** Laurent Boucher

## Contexte

Vectispire est en pré-1.0 (`README.md`) et le dit : « There is no long-term support line yet »
(`SECURITY.md`). Rien d'écrit ne dit ce qu'une 1.0 garantirait, donc rien ne dit ce qui doit être vrai
avant d'en publier une. Chaque mineure jusqu'ici a changé ce que voit une intégration — 40 points de ce
genre en 0.10, 49 en 0.11 — ce qui est juste pour un projet qui cherche sa forme, et faux pour un projet
qui demande à des pipelines, des auditeurs et des agents sur d'autres machines de dépendre de lui.

Cinq faits rendent la question concrète :

- **L'API est figée par un test, pas par une promesse.** `ClientContractSpecTest` échoue quand
  `openapi.json` dérive ; régénérer le fichier le fait repasser. Il détecte un changement, il ne refuse pas
  un changement cassant. Aucune opération n'a jamais été marquée dépréciée.
- **Le protocole des agents a cassé sans le dire.** `AgentContract.VERSION` vaut `"1"`, comparé par
  égalité stricte, et 0.11.0 ne confie aucun travail à un agent antérieur à 0.11.0 (l'enveloppe scellée
  `v2`) — avec une version toujours à `"1"`. Le refus bruyant que la comparaison stricte devait produire
  n'a pas eu lieu.
- **Les moteurs que nomme la documentation ne sont pas ceux qui sont testés.** Le guide d'installation
  dit MySQL 8 ; la campagne d'intégration tourne sur `mysql:9.4` et `postgres:17.6` ; l'exercice de
  restauration tourne sur `mysql:8` et n'a pas de cas PostgreSQL.
- **Deux plans de contrôle n'ont jamais tourné ensemble.** [0038](0038-deploying-on-kubernetes.md)
  consigne qu'aucun test ne fait tourner deux réplicas ; les tâches de maintenance en supposent un.
- **Une seule personne peut publier une version et répondre à un signalement de sécurité.** Le code de
  conduite promet qu'un mainteneur mis en cause ne traite pas le signalement, ce qu'un mainteneur seul ne
  peut pas tenir.

## Décision

1.0 est publiée quand les cinq promesses ci-dessous sont écrites, exécutées par une vérification là où
c'est possible, et ont tenu pendant une version mineure sans rupture imprévue.

### 1. L'API REST est additive dans `/api/v1`

- Dans `/api/v1`, une version peut **ajouter** des routes, des champs de requête facultatifs, des champs
  de réponse et des valeurs d'énumération. Elle ne retire ni ne renomme une route ou un champ, ne
  restreint pas ce qu'une requête accepte, et ne change pas le sens d'un champ.
- Un retrait est **annoncé, puis fait deux versions mineures plus tard** : l'opération ou le champ est
  marqué `deprecated` dans `openapi.json`, les notes de version le nomment avec son remplaçant, et il
  continue de fonctionner entre-temps. Un changement qui ne peut pas se faire ainsi est `/api/v2`.
- **Les appels de l'interface relèvent de la même règle.** Ils utilisent la même API ; une seconde
  surface instable à côté de la stable serait un second contrat à tenir séparé, et la première
  intégration qui copierait un appel depuis le navigateur en dépendrait de toute façon.
- **Vérifié par la CI** : un diff de compatibilité d'`openapi.json` contre le dernier tag de version fait
  échouer le build sur un changement cassant qui n'est pas un retrait annoncé deux mineures plus tôt.
- Les clients ignorent les champs de réponse qu'ils ne connaissent pas. Les énumérations sont ouvertes :
  un client qui rencontre une valeur inconnue l'affiche telle qu'envoyée (l'interface le fait déjà,
  [0019](0019-screen-text-is-translated-on-the-client.md)).

### 2. Un agent d'une version mineure en retard sur le plan de contrôle est servi

- Le plan de contrôle sert un agent de sa propre mineure et de la **précédente** (N-1). Mettre à niveau le
  plan de contrôle d'abord, puis les agents, est pris en charge ; l'inverse ne l'est pas.
- `AgentContract` porte une **plage**, plus une valeur unique, et un changement que l'agent de la mineure
  précédente ne comprendrait pas — une nouvelle enveloppe, un nouveau champ obligatoire — se fait en deux
  temps : le plan de contrôle accepte les deux formes pendant une mineure, la suivante retire l'ancienne.
- Cela accepte le coût que nomme la javadoc d'`AgentContract` : pour chaque champ ajouté, quelqu'un décide
  si un agent qui l'ignore reste correct. Un **test de compatibilité** en décide — l'agent de la version
  précédente, depuis son image publiée, contre le plan de contrôle courant, qui réclame et termine un
  scan — plutôt que la mémoire du relecteur.
- L'alternative était le pas strictement synchronisé. Plus simple, et faux pour les déploiements qu'il
  rencontrerait : sur Kubernetes, le plan de contrôle et les agents se mettent à jour à des moments
  différents, et un refus strict pendant cette fenêtre arrête tous les scans.

### 3. Un moteur, MySQL, à des versions nommées

- **MySQL 8.4 LTS et 9.x.** La campagne d'intégration tourne sur la plus ancienne et la plus récente
  version prise en charge ; le guide d'installation nomme exactement celles-ci.
- L'exercice de restauration et le job de mise à niveau (§6) tournent sur MySQL.
- Une version de moteur quitte la liste dans une version mineure, annoncée dans les notes de la précédente.
- **PostgreSQL ne fait pas partie de 1.0** (amendement du 2026-10-29 ; cette section le promettait d'abord à
  côté de MySQL). Son code reste — les migrations par moteur sous `db/migration/postgresql/`, le pilote, les
  substitutions du dialecte, `Engine.POSTGRES` — mais aucun job de CI ne l'exécute, et rien ne promet qu'il
  fonctionne. Une migration dont la structure diverge s'écrit toujours deux fois (`MigrationLayoutTest` le
  vérifie sans serveur) : le code ne se dégrade pas sur le schéma ; il peut se dégrader sur une requête, et
  rien ne le dirait.
- **Pourquoi un seul moteur.** Chaque moteur double la campagne d'intégration, les exercices de mise à
  niveau et de restauration, et les cas qu'une relecture doit envisager, pour un parc qui tourne sur
  MySQL — le moteur que livre la composition et celui de la production. Quatre serveurs à garder verts
  (deux versions de chaque) était le prix de la première rédaction ; deux est celui de celle-ci.
- **Ramener PostgreSQL** est une version mineure à part entière : sa campagne et ses exercices repassent au
  vert sur des versions nommées, et le guide d'installation le liste. Le code conservé fait de ce retour
  une affaire de vérifications plutôt que d'écriture.

### 4. Une seule instance du plan de contrôle est promise

- 1.0 prend en charge **un** réplica du plan de contrôle. La chart reste à un par défaut ; la documentation
  dit qu'un second réplica n'est pas pris en charge, et pourquoi (tâches de maintenance, verrou de la
  chaîne d'audit, outbox).
- La haute disponibilité est un objectif de 1.x avec sa propre décision, prise quand deux réplicas
  tourneront dans un test.
- Promettre la HA maintenant promettrait ce qu'aucune vérification n'exécute (« une garantie qui n'est pas
  exécutée n'est pas une garantie », `AGENTS.md`).

### 5. Une ligne maintenue, et les personnes derrière elle

- **La dernière mineure** reçoit les corrections. **La mineure précédente** reçoit les corrections de
  sécurité pendant **trois mois** après la sortie de la suivante. `SECURITY.md` nomme les lignes maintenues
  et la date de fin de chacune.
- Une version corrective n'exige jamais une migration qu'une mineure ultérieure ne porterait pas aussi :
  une correction qui en exige une va dans la mineure suivante, ou sa migration prend une version réservée
  à la ligne (la règle de numérotation est écrite avant le premier correctif 0.11.x).
- **Un second mainteneur**, capable de publier une version et de traiter un signalement de sécurité,
  existe avant 1.0.
- **L'emplacement définitif du dépôt est fixé avant 1.0.** Les signatures des versions nomment le dépôt,
  son propriétaire et le fichier de workflow ; le déplacer ensuite invalide toutes les signatures qu'un
  consommateur a appris à vérifier.

### 6. Ce qui doit être vrai avant le tag

Outre les cinq promesses, les contrats que 1.0 fige sont d'abord remis d'aplomb, parce que les figer en
l'état figerait leurs défauts :

- les motifs de refus de la barrière portent un **code lisible par une machine** à côté de la phrase (les
  pipelines analysent aujourd'hui un texte anglais) ;
- le prédicat d'attestation passe en **v2** avec une seule unité pour ses comptes (`findings.total` compte
  des issues, les sévérités des occurrences) ;
- les codes de conformité sont arrêtés (numérotation 2022 des codes CRA, libellés OWASP Top 10:2025) ;
- le manifeste des plugins de scan porte une **version de schéma**, comme l'export des plugins de rapport
  le fait déjà ;
- les champs `reachability` dépréciés sont retirés — avant la promesse, pas deux mineures après ;
- un **job de mise à niveau N-1 → N** tourne chaque nuit sur les deux moteurs, sur une base qui contient
  des données, et une restauration est effectuée sur chacun.

## Conséquences

- Un changement cassant de l'API après 1.0 coûte deux versions mineures ou une `/api/v2` ; le diff en CI
  rend le coût visible à la pull request, pas dans le pipeline d'un consommateur.
- Chaque changement côté agent se conçoit en deux temps, et le test de compatibilité fait tourner l'image
  de l'agent de la version précédente à chaque build de `develop` — une CI plus lente, et la seule façon
  dont la promesse tient.
- La liste des moteurs pris en charge garde la campagne d'intégration à deux serveurs, tous deux MySQL.
  Une installation sur PostgreSQL passe à MySQL avant 1.0 ou reste en 0.x.
- Les corrections de sécurité sont reportées sur la mineure précédente pendant trois mois : un coût en
  temps de mainteneur que le second mainteneur est là pour partager.
- Tant que cela ne tient pas, le projet reste en 0.x et le dit ; rien ici ne change ce que promet 0.11.

## Écarté

- **Le pas strictement synchronisé entre agents et plan de contrôle** — plus simple, et arrête tous les
  scans à chaque mise à jour progressive (§2).
- **Une API interne distincte pour l'interface** — un second contrat à tenir séparé, dont on dépendrait de
  toute façon (§1).
- **La HA en 1.0** — rien ne l'exécute aujourd'hui (§4).
- **Deux moteurs, PostgreSQL 16 et suivantes à côté de MySQL** — la première rédaction du §3. Écarté le
  2026-10-29 : les vérifications existaient, mais les garder vertes sur deux versions de chaque moteur coûte
  plus que ne le rend un parc qui tourne sur MySQL. Le code est conservé pour que le choix reste réversible
  (§3).
