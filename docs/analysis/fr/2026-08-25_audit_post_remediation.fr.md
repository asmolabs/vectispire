# Audit Post-Remédiation : Documentation, Code Source & Sécurité (Français)

* **Projet :** Vectispire — Control Plane ASPM & Sécurité Logicielle
* **Date d'analyse :** 25 août 2026 (seconde passe, après remédiation)
* **Évaluateur :** Claude (Anthropic) — audit automatisé du code, de la sécurité et de la documentation
* **Référence :** [Rapport d'Audit Approfondi, même jour](2026-08-25_audit_approfondi_code_securite_doc.fr.md) — 7,9 / 10, quatorze constats
* **Méthode :** Re-vérification contre l'arbre courant, la remédiation elle-même étant le premier objet d'examen. Contrôles mécaniques rejoués de zéro ; aucun constat n'est repris comme « corrigé » sur la foi d'un message de commit.

> **À quoi sert cette passe.** Le premier audit a trouvé des contrôles correctement conçus et incorrectement câblés. Un millier de lignes environ ont ensuite été modifiées en sécurité, en build et en documentation pour les fermer. **Le code neuf est là où sont les défauts neufs, et le code de remédiation s'écrit dans les pires conditions de relecture — vite, par celui qui vient de trouver le problème, avec la satisfaction de l'avoir trouvé.** Cette passe commence donc par la remédiation et n'élargit qu'ensuite.

---

## 📊 1. Synthèse & Notes

| Domaine évalué | Avant | Maintenant | Statut |
|---|:---:|:---:|:---:|
| **Documentation & Architecture** | 7,5 | **9,0 / 10** | 🟢 **Rendue à sa structure** |
| **Sécurité & Cryptographie** | 7,0 | **8,8 / 10** | 🟢 **Câblée, et testée à travers la chaîne** |
| **Qualité du Code & Architecture** | 8,5 | **8,7 / 10** | 🟢 **Prêt pour l'entreprise** |
| **Conformité Réglementaire & Standards** | 8,5 | **9,2 / 10** | 🟢 **Se mesure désormais elle-même** |
| **Global** | **7,9** | **8,9 / 10** | 🟢 |

**Les quatorze constats et les deux réserves du §5 se vérifient comme fermés.** La note ne monte pas
plus haut pour trois raisons, et elles constituent la substance de ce rapport : un nouveau défaut de
performance d'une classe que le projet s'interdit explicitement ailleurs, deux défauts trouvés
*dans la remédiation elle-même* au cours de cette passe, et un ensemble de contrôles désormais
corrects mais pas encore éprouvés dans l'environnement qui les exécutera.

### Trouvés dans la remédiation, pendant cette passe

Les deux ont été introduits par les correctifs des constats précédents et sont corrigés dans le
même commit que ce rapport. Ils viennent en premier parce qu'ils sont la réponse à « la réparation
a-t-elle tenu ».

| # | Défaut | Sévérité | Traitement |
|:--:|---|:--:|---|
| **P1** | `ComplianceService.platformPosture()` appelait `verifyAgainstMirror()`, qui lit **tout le fichier miroir et toutes les lignes d'audit** pour les comparer — à chaque affichage de la page conformité. Un booléen suffisait. | 🟠 **Élevée** (performance) | ✅ Corrigé : un nouveau `AuditLogService.mirrorConfigured()` répond à la question sans la comparaison. |
| **P2** | `finalizedBy(tasks.withType<JacocoReport>())` rattachait le rapport de couverture à *chaque* tâche Test : exécuter `integrationTest` seul générait un rapport à partir de `test.exec` — un chiffre de couverture décrivant une autre exécution. | 🟡 **Moyenne** | ✅ Corrigé : restreint à la tâche `test`. |

P1 est le plus instructif. Le correctif du constat §3.6 avait besoin de savoir si un miroir d'audit
existe ; la méthode qui répondait venait avec une comparaison d'intégrité complète attachée, et y
recourir était gratuit au moment de l'écrire et coûteux au moment de l'exécuter. **Un correctif de
justesse qui devient discrètement un défaut de performance est la défaillance caractéristique du
travail de remédiation**, et c'est la raison d'être de cette passe.

### Nouveau constat dans le code préexistant

| # | Constat | Sévérité | Preuve |
|:--:|---|:--:|---|
| **N1** | `/api/v1/compliance/summary` émet **neuf requêtes de comptage par cible** dans sa boucle par cible, plus un balayage complet de la table d'audit pour la vérification de chaîne. Sur cent cibles, cela fait ~900 allers-retours pour une page. | 🟠 **Élevée** | [ComplianceService.java:175](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/ComplianceService.java) |

Celui-ci mérite une formulation précise, car le projet connaît déjà la règle. `TriageEvents.findForIssues` porte ce commentaire :

> *« Une requête pour une page d'anomalies, pas une par anomalie. […] interroger par ligne transforme une page en des centaines d'allers-retours, ce qui est invisible sur une base de démonstration et fait la différence entre un écran et un délai dépassé sur un vrai backlog. »*

C'est exactement ce que fait la synthèse de conformité. La règle est énoncée dans le code et violée
dans le service qui produit le rapport que lit un auditeur. Elle est invisible sur la campagne
SQLite, pour la raison que donne le commentaire.

**Correctif :** une requête groupée par compteur (`GROUP BY repo_id, container_id`) alimentant une
table, et borner la vérification de chaîne — voir R5.

---

## 📚 2. Documentation & Architecture — 9,0

**Vérifié mécaniquement, pas supposé :**

| Contrôle | Avant | Maintenant |
|---|:---:|:---:|
| Liens relatifs qui résolvent | 252 / 305 | **325 / 325** |
| Chemins absolus `file:///Users/...` dans la doc livrée | 4 | **0** |
| `ROTATION_AND_PURGE` FR / EN | 37 / 202 | **202 / 202** |
| `TECHNICAL_DOCUMENTATION` FR / EN | 212 / 513 | **518 / 514** |
| `COMPLIANCE_AND_REGULATORY` EN / FR | 204 / 266 | **302 / 308** |

Le vérificateur de liens est désormais un job de CI : le compte est donc défendu et pas seulement
corrigé — et il rejette tout lien `file://` par construction, ce qui est la régression précise qui
avait produit la fuite du répertoire personnel.

La documentation technique française n'était pas une traduction abrégée mais un autre document au
plan différent ; elle reflète désormais la structure anglaise sur les quatorze sections. Ses deux
sections de conformité ont été supprimées plutôt que traduites, à juste titre : elles dupliquaient
`COMPLIANCE_AND_REGULATORY.fr`, où ce contenu a sa place.

**Ce qui l'empêche d'atteindre 9,5 :** `GETTING_STARTED.fr` reste 11 % plus court que son homologue
anglais (187 contre 211) — les structures divergent là où le français isole le déploiement Docker
dans sa propre section. La parité de contenu est atteinte ; la parité de lignes non, et l'écart est
cosmétique plutôt qu'un déficit de couverture.

---

## 🛡️ 3. Sécurité & Cryptographie — 8,8

### Vérifiés fermés

- **Connexion MFA joignable.** `/api/v1/auth/mfa/verify` est en `permitAll`, et — plus durable que le correctif — `RouteAuthorizationTest.anOpenRouteIsReallyReachableWithoutCredentials` parcourt chaque route `@OpenToAnonymous` et vérifie qu'un handler a été atteint plutôt qu'un statut, puisqu'une route ouverte peut légitimement répondre 401 elle-même. Re-vérifié par mutation pendant cette passe : retirer le `permitAll` fait échouer la sonde sur `POST /api/v1/auth/mfa/verify → refusé par la chaîne de filtres avec 401`.
- **Force brute TOTP bornée.** Trois tentatives par défi, défi détruit au dernier échec, message identique dans les deux cas. Re-vérifié par mutation : désactiver la destruction fait échouer `exhaustedChallengeIsDestroyed`.
- **Limiteur indexé sur ce que le client ne choisit pas.** `X-Forwarded-For` n'est honoré que derrière un proxy de confiance configuré, parcouru de droite à gauche jusqu'au premier hop non fiable ; les buckets forment une LRU bornée élaguée à l'insertion et non sur le chemin de rejet qu'un attaquant ne prend jamais.
- **Le quatre-yeux compte des personnes, pas des rôles.** L'approbateur est comparé à l'acteur de l'événement `PENDING_APPROVAL`, lu depuis le journal d'événements parce que `triagedBy` sur la ligne est déjà écrasé à ce moment. Vérifié par mutation : sans le contrôle, l'auto-approbation renvoie 200.
- **Le déploiement échoue fermé.** `docker compose config` refuse de rendre le fichier sans `ENCRYPTION_KEY`, le mot de passe de base et le mot de passe d'amorçage. `group_add` accorde le groupe de la socket que le Dockerfile documentait déjà comme nécessaire ; la base est liée à la boucle locale.
- **Vault échoue vite.** `kms-type=vault` sans point de terminaison ni jeton joignable refuse de démarrer au lieu de déplacer silencieusement la garde des clés vers une dérivation locale.
- **Les conteneurs de scan tournent sur un rootfs en lecture seule**, avec un tmpfs `noexec` pour l'espace de travail. Validé sur un démon réel contre les cinq images épinglées, et vérifié par quatre cas de la campagne d'intégration conteneurs.

### Ce qui maintient la note à 8,8

| # | Résiduel | Pourquoi cela compte |
|:--:|---|---|
| **R2** | La MFA a des tests de route mais **aucune couverture de bout en bout** — `auth.spec.ts` ne contient toujours aucun cas MFA. | Le défaut d'origine était une divergence chaîne/annotation que seule une requête HTTP pouvait révéler. Cette classe est désormais couverte par MockMvc ; le chemin navigateur ne l'est pas. |
| **R3** | Le miroir d'audit reste **désactivé par défaut**. | Justifié — écrire dans un chemin par défaut échoue sur un système de fichiers de conteneur en lecture seule — et son absence est désormais *visible* dans le score de conformité au lieu d'être silencieuse. Mais le cas de la feuille supprimée reste ouvert sur une installation par défaut. |
| **R6** | L'exposition anonyme de la doc d'API est désormais un réglage, **fermé par défaut** ; les endpoints springdoc sous-jacents sont eux aussi désactivés par défaut. | Correct, et l'échappée belle mérite d'être notée : la première implémentation avait l'air juste et ne faisait rien, parce que la règle de lien profond du SPA attrapait `/v3/api-docs` en premier. Elle n'a été prise que parce que le test vérifiait le refus au lieu du réglage. |

**Sur l'exception Grype, qu'un évaluateur ne manquera pas de soulever.** Chaque conteneur de scan
tourne avec un rootfs en lecture seule, à ceci près que la base de vulnérabilités vit désormais sur
un montage inscriptible sur disque. Ce n'est pas un affaiblissement : la base pèse environ 1,9 Go,
le tmpfs de travail est de la mémoire comptée sur un plafond conteneur de 2 Go, et ce montage est le
*seul* chemin inscriptible dont dispose le conteneur. Mesuré contre le démon réel — la version
tmpfs seule échouait avec `no space left on device` puis `database does not exist`, ce qui se serait
lu comme une panne de scanner et non comme une erreur de dimensionnement. Livrée sur la foi de la
relecture, chaque analyse de dépendances aurait échoué.

---

## ⚙️ 4. Qualité du Code & Architecture — 8,7

**Spring Boot 4.1.0 / JDK 25, 177 classes de test unitaire, 7 classes d'intégration, zéro
`TODO`/`FIXME` dans les sources de production.** Les six règles ArchUnit tiennent toujours, y
compris la garde d'import vide qui empêche une campagne d'architecture de passer à vide.

**La couverture est désormais mesurée et défendue.** JaCoCo émet du XML, et un plancher
`jacocoTestCoverageVerification` restreint à `common.domain` (80 % instructions, 65 % branches) est
rattaché à `check`. Actuel : **83,6 % instructions, 69,4 % branches** — au-dessus du plancher, avec
la marge qu'un plancher doit avoir. Vérifié par mutation : le porter à 95 % fait échouer la
construction sur le chiffre mesuré. Le restreindre au domaine pur est juste — c'est la couche
qu'ArchUnit garde libre de tout framework précisément pour qu'elle soit exhaustivement testable, et
un plancher sur la tuyauterie mesurerait le nombre de ses accesseurs.

**La CI couvre désormais ce qu'elle se contentait de divulguer.** `nightly.yml` exécute
`integrationTestAll` sur quatre moteurs et les campagnes Playwright à 02:30 UTC. Le job E2E démarre
d'abord le control plane sur SQLite — ce que l'état antérieur n'aurait jamais pu faire, puisque le
`webServer` de Playwright ne lance que `ng serve` et que son proxy exige une API sur `:3180`.

### Ce qui maintient la note à 8,7

| # | Résiduel | Pourquoi cela compte |
|:--:|---|---|
| **N1** | Le N+1 de conformité ci-dessus. | La règle est énoncée dans ce code et rompue dans ce même code. |
| **R1** | **`nightly.yml` n'a jamais été exécuté.** Il est syntaxiquement valide et sa logique est raisonnée, mais un workflow planifié est une hypothèse tant qu'il n'a pas tourné une fois. | Le job E2E en particulier fait des hypothèses sur le temps de démarrage, le comportement de SQLite sous `ddl-auto: validate` et Playwright sur un runner nu. Déclenchez-le une fois à la main (`workflow_dispatch`) avant de faire confiance à la pastille verte. |
| **R5** | `AuditLogService.verify()` lit **toutes les lignes d'audit** sans borne, et la synthèse de conformité l'appelle à chaque affichage. | Préexistant, et de même forme que N1. Sur une instance mûre, le journal d'audit est la plus grosse table. |

---

## 📋 5. Conformité Réglementaire & Standards — 9,2

C'est là que se situe la plus grande amélioration réelle, et ce n'est pas un changement de
documentation.

**Le moteur mesure désormais le control plane, et pas seulement la flotte.** Le comportement
antérieur était plus tranchant que ne le disait le premier audit : une instance tournant **sans
aucune clé de chiffrement** — détenant des clés SSH de déploiement qu'elle ne pouvait pas protéger —
affichait *« Zero exposed plaintext credentials detected »* et scorait **100/100** sur
`DORA-ART13-SECRETS`, parce que le seul élément consulté par ce contrôle était la sortie de Gitleaks
sur les dépôts *des autres*. Le constat était vrai ; la conclusion ne l'était pas.

Une entrée `PlatformPosture` porte désormais ce que ce déploiement a activé, et un contrôle est
plafonné à **PARTIAL** quand la capacité qui le porte est éteinte :

| Catégorie | Plafonné quand | Plafond |
|---|---|:---:|
| `SECRETS_MANAGEMENT` | aucune clé de chiffrement configurée | 60 |
| `AUDIT_AND_LOGGING` | aucun miroir d'audit configuré | 70 |
| `GOVERNANCE` | quatre-yeux désactivé | 75 |

Trois décisions de conception méritent d'être consignées, car chacune retire un moyen au contrôle
de mentir :

1. **Une entrée séparée, pas quatre champs de plus dans `PostureInput`.** L'une mesure le code de quelqu'un d'autre ; l'autre décrit ce déploiement. Un évaluateur les traite différemment, le type devrait aussi.
2. **Aucune surcharge par défaut.** Les cinq appelants déclarent la posture explicitement ; le compilateur pose la question au lieu qu'un défaut silencieux y réponde. C'est ce qui a fait échouer la compilation de la campagne de tests, ce qui était le comportement voulu.
3. **Le plafond ne fait que baisser.** Un contrôle déjà en échec sur les constats continue de le dire — le passer à PARTIAL parce qu'un interrupteur est éteint serait une amélioration gagnée par un second défaut. Vérifié par `aCapNeverImprovesAnAssessment`.

**Les limites de la piste d'audit sont désormais énoncées là où un évaluateur les lit.** Le §5.1 du
document de conformité, dans les deux langues, dit ce que la chaîne prouve (une modification
sélective est détectable), ce qu'elle ne prouve pas (la suppression d'une entrée dont personne ne
descend ne l'est pas), pourquoi cette concession a été prise (une chaîne strictement linéaire
faisait déclarer rompu un journal honnête écrit par des instances concurrentes), et ce qui la ferme
(le miroir). Un système de points de contrôle en base a été envisagé et écarté par écrit : qui peut
écrire dans la table d'audit peut réécrire une table de points de contrôle de façon cohérente, ce
qui déplacerait le problème d'un cran tout en ayant l'air d'une preuve.

**Ce qui l'empêche d'atteindre 9,5 :** le cas de la feuille supprimée reste ouvert sur une
installation par défaut, puisque le miroir est désactivé par défaut. C'est désormais honnête plutôt
que caché — la note le dit — mais honnête et fermé ne sont pas la même chose.

---

## 🎯 6. Recommandations

### 🟠 Ensuite
1. **Réduire le N+1 de conformité** à des requêtes groupées, et borner la vérification de chaîne que la synthèse déclenche *(N1, R5)*.
2. **Exécuter `nightly.yml` une fois à la main** via `workflow_dispatch` et corriger ce qu'il révèle, avant que la planification ne rende sa première pastille verte signifiante *(R1)*.
3. **Ajouter un cas MFA à `auth.spec.ts`** — le chemin navigateur du défaut qui a tout déclenché *(R2)*.

### 🟡 Plus tard
4. Amener `GETTING_STARTED.fr` à la parité de lignes, ou assumer explicitement la divergence structurelle.
5. Envisager un chemin de miroir par défaut pour les déploiements conteneurisés, où un volume inscriptible existe déjà *(R3)*.
6. Étendre le plancher de couverture au-delà de `common.domain` une fois la forme des requêtes du service de conformité stabilisée.

---

## 7. Conclusion

La remédiation tient. Chacun des quatorze constats et les deux réserves du §5 se vérifient comme
fermés en re-testant, et plusieurs ont été vérifiés par mutation plutôt que par inspection — en
retirant le correctif et en regardant le bon test échouer, seule preuve qu'un test défend ce qu'il
prétend défendre.

Ce que cette passe ajoute est la part qu'une auto-évaluation omet d'ordinaire. Deux défauts ont été
introduits par la réparation elle-même — une lecture de table complète placée sur un chemin
d'affichage de page, et un rapport de couverture rattaché à la mauvaise exécution — et tous deux ont
été trouvés ici plutôt qu'en production. Un défaut préexistant de conséquence réelle n'a émergé que
parce que le service de conformité a été lu de près pour d'autres raisons : il rompt, dans le
service qui produit le rapport d'un auditeur, une règle que ce code énonce dans sa propre couche de
repositories.

**8,9 / 10**, c'est un code dont les contrôles sont désormais câblés comme ils étaient conçus, dont
la documentation est défendue mécaniquement, et dont le moteur de conformité a cessé de s'exempter
de la norme qu'il applique à tous les autres. Ce qui le sépare de mieux n'est pas l'architecture :
c'est une forme de requête, un workflow qui n'a jamais tourné, et un chemin navigateur encore non
testé.
