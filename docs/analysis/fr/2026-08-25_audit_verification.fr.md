# Audit de Vérification : Documentation, Code Source & Sécurité (Français)

* **Projet :** Vectispire — Control Plane ASPM & Sécurité Logicielle
* **Date d'analyse :** 25 août 2026 (quatrième passe)
* **Évaluateur :** Claude (Anthropic) — audit automatisé du code, de la sécurité et de la documentation
* **Périmètre :** Les quatre axes de [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)
* **Rapports antérieurs :** [Approfondi](2026-08-25_audit_approfondi_code_securite_doc.fr.md) (7,9) → [Post-Remédiation](2026-08-25_audit_post_remediation.fr.md) (8,9) → [Quatre Axes](2026-08-25_audit_approfondi_4_axes.fr.md) (8,7)

> **Ce que cette passe apporte, et pourquoi c'est la bonne chose à faire.** Treize commits ont été
> livrés depuis le dernier rapport, plusieurs sur des chemins critiques — l'étape secrets, la
> résolution des images de scanners, la forme des requêtes de conformité, le déploiement
> conteneurisé. **La remédiation est l'endroit où les défauts sont les plus frais**, donc cette
> passe a *exécuté* le code plutôt que de le lire : le control plane a été démarré contre
> PostgreSQL et MySQL, de vraies lignes insérées, les endpoints appelés. Deux passes précédentes
> se sont fait prendre par des tests tournant sur une base vide ; celle-ci ne répète pas l'erreur.

---

## 📊 1. Tableau Récapitulatif des Notes

| Domaine évalué | Quatre Axes | Cette passe | Statut |
|---|:---:|:---:|:---:|
| **Documentation & Architecture** | 8,8 | **9,2 / 10** | 🟢 Artefacts générés désormais défendus |
| **Sécurité & Cryptographie** | 8,5 | **9,1 / 10** | 🟢 Le chemin des secrets fermé, vérifié |
| **Qualité du Code & Architecture** | 8,3 | **8,9 / 10** | 🟢 Vérifié sur trois moteurs |
| **Conformité Réglementaire & Standards** | 9,2 | **9,3 / 10** | 🟢 Certifiable |
| **Global** | 8,7 | **9,1 / 10** | 🟢 |

**Tous les constats des trois rapports précédents se vérifient fermés**, et les trois qui restaient
ouverts (A1, A2, A3) ainsi que les six recommandations sont faits. Ce qui maintient la note sous
9,5 est énoncé au §6 : un réglage documenté qui n'existe pas, un moteur jamais exercé de bout en
bout, et une affirmation du prompt lui-même que le code contredit sur un point réel quoique étroit.

### Ce qui a été vérifié en exécutant, pas en lisant

| Contrôle | Méthode | Résultat |
|---|---|---|
| La nouvelle requête groupée du sommaire de conformité | Jar packagé démarré contre **PostgreSQL** puis **MySQL**, vraies anomalies insérées, endpoint appelé | ✅ 4 et 2 anomalies correctement attribuées ; **aucune `ClassCastException`** |
| Validation de schéma par moteur | Les deux mêmes démarrages sous le `ddl-auto: validate` livré | ✅ Les deux démarrent proprement |
| Déterminisme de l'export C4 | Exporté deux fois, comparé | ✅ Identique au octet près — sûr à barrer |
| Détection de dérive C4 | `workspace.dsl` modifié, contrôle relancé | ✅ Échoue, comme il le doit |
| Propriétaire du volume nommé du miroir d'audit | Image jetable construite, volume vide monté | ✅ Docker hérite du propriétaire du répertoire de l'image ; le miroir peut écrire |
| Compose échoue fermé | `docker compose config` sans secrets | ✅ Refusé |
| Liens de documentation | 354 liens relatifs résolus | ✅ 0 cassé |

**Le risque que cela ferme.** La requête groupée renvoie des lignes `Object[]` que le service caste.
Elle n'était exercée que sur SQLite par la campagne unitaire, et le sommaire de conformité ne fait
pas partie de la campagne d'intégration sur quatre moteurs — un cast erroné serait donc apparu comme
un 500 sur la page phare du moteur par défaut, en production, sans que rien n'échoue avant. Il est
correct ; c'est désormais su plutôt que supposé.

---

## 📚 2. Documentation & Architecture — 9,2

**Modèle Bertrand Florat** : cinq vues, deux langues, parité de lignes exacte (88/75/52/66/73).
**STRIDE** : E1–E4, P1–P5, DS1–DS2, F1–F16, les six catégories, 171 lignes de chaque côté.
**ADR** : treize, chaîne de remplacement intacte.
**Liens** : 354 résolus, 0 cassé, défendus par le job de CI `docs`.

**Le C4 est désormais de l'architecture-as-code en fait, et plus seulement en intention.** Les
`.puml` committés correspondent à un export frais de `workspace.dsl`, et la CI les compare à chaque
push. Seul l'export texte est barré — vérifié reproductible en exportant deux fois — parce que les
PNG de PlantUML en sont un rendu, et qu'un contrôle de dérive instable apprend à relancer le job
jusqu'à ce qu'il passe. Six artefacts orphelins `structurizr-*-key` ont été retirés : référencés
nulle part, produits par aucun exporteur actuel, ils ne pouvaient que se périmer.

**Parité bilingue, mesurée :**

| Document | EN | FR |
|---|:--:|:--:|
| `ROTATION_AND_PURGE` | 202 | 202 |
| `SECURITY_AND_QUALITY_REVIEW` | 148 | 148 |
| `TECHNICAL_DOCUMENTATION` | 514 | 518 |
| `COMPLIANCE_AND_REGULATORY` | 302 | 308 |
| `GETTING_STARTED` | 211 | 235 |

Le français mène désormais sur trois, et la divergence structurelle qui explique
`GETTING_STARTED` — le français garde le déploiement conteneurisé en section propre là où l'anglais
en fait un §5.1 — est consignée dans le document lui-même, de sorte qu'un écart de numérotation ne
puisse pas se lire comme une dérive de traduction.

---

## 🛡️ 3. Sécurité & Cryptographie — 9,1

### 3.1 Contrôles vérifiés

| Contrôle | État |
|---|---|
| Limitation de débit | ✅ Token-bucket en amont d'Argon2id ; `X-Forwarded-For` uniquement derrière un proxy de confiance configuré ; LRU bornée élaguée à l'insertion |
| Argon2id, MFA TOTP | ✅ Joignable, tentatives plafonnées, vérifié par mutation — et désormais couvert de bout en bout |
| SCIM 2.0 / OIDC | ✅ `/scim/v2/{Users,Groups}` sous `@RequiresAdministrator` ; claim `groups` associé aux équipes |
| AES-256-GCM, KMS Vault | ✅ Contexte lié à la ligne ; `kms-type=vault` refuse de démarrer sans point de terminaison joignable |
| Bac à sable des scanners | ✅ `cap_drop: ALL`, `no-new-privileges`, `network: none` par défaut, épinglé par digest, rootfs en lecture seule, espace de travail `noexec`, aucune socket Docker |
| Chaîne d'audit | ✅ Chaînée ; limites énoncées au §5.1 du document de conformité ; **miroir désormais actif par défaut en compose** |
| Quatre-yeux | ✅ Identités distinctes, vérifié par mutation |

### 3.2 L'étape secrets, fermée et rendue inexprimable

Le constat le plus grave de la passe précédente — le seul endroit où la décision 0007 n'était pas
appliquée, dans le type de constat où une fausse résolution coûte le plus cher — est corrigé. Les
deux scanners de secrets renvoient `Optional`, les deux sont routés par `ran(…)`, et l'exception
avalée a disparu.

Deux choses le rendent durable plutôt que simplement corrigé :

* `ScannerContractTest` vérifie par réflexion que chaque scanner lançant un conteneur renvoie un
  `Optional`, identifié par le fait qu'il détient un `ContainerRunner` et non par son nom : un
  scanner ajouté dans six mois entre dans le périmètre dès qu'il existe.
* Remettre `BetterleaksScanner` à une `List` nue **ne compile plus** — `ran(…)` exige un `Optional`.
  Le défaut est devenu inexprimable, ce qui est plus fort que testé.

### 3.3 Isolation de l'agent — réelle, et plus étroite qu'une lecture rapide

Le prompt décrit une « isolation étanche de l'agent distant : zéro JDBC, zéro `ENCRYPTION_KEY`,
communication sortante uniquement ». Vérifié, avec une nuance qui mérite d'être au dossier :

* **Zéro JDBC** — imposé par le graphe de modules et non par convention : `vectispire-agent` ne
  dépend pas de `vectispire-core`, aucun pilote n'est sur le classpath de compilation et la
  violation échoue à la compilation. `AgentIsolationTest` le réaffirme et se garde d'un import vide.
* **Zéro `ENCRYPTION_KEY`** — confirmé : rien dans le module agent ne la lit.
* **Sortant uniquement** — `web-application-type: none`, l'agent n'ouvre donc aucun port, et
  `AgentHttp` pose `Redirect.NEVER`.
* **Mais l'agent reçoit bien des clés de déploiement**, en `credentialsMode: delegated` — dans un
  `SealedEnvelope` adressé à la paire de clés qu'il a annoncée à l'enrôlement. « L'agent ne détient
  aucun identifiant » serait trop fort ; l'affirmation exacte est qu'il ne détient jamais la clé de
  chiffrement de la plateforme, n'atteint jamais la base, et ne reçoit les clés de dépôt que
  scellées à lui-même. Le code refuse une enveloppe qu'il ne peut pas ouvrir plutôt que de passer
  le chiffré à git — où l'échec se serait lu comme un problème de permissions.

Cette précision mérite d'être gardée : c'est la différence entre une affirmation qu'un évaluateur
peut vérifier et une qu'il dévaluera.

---

## ⚙️ 4. Qualité du Code & Architecture Logicielle — 8,9

**Spring Boot 4.1.0 / JDK 25**, 178 classes de test unitaire, 7 classes d'intégration, zéro
`TODO`/`FIXME` en production. ArchUnit impose six règles dont la garde d'import vide. JaCoCo
plafonne `common.domain` à 80 % instructions / 65 % branches, rattaché à `check` ; actuel
**83,6 % / 69,4 %**.

**Le N+1 de conformité a disparu** : neuf requêtes de comptage par cible sont devenues une requête
groupée plus une lecture des dépassements — deux pour toute la page. La visibilité est appliquée par
l'appelant et non dans la requête, ce qui est équivalent puisqu'elle est purement scopée par cible.
La vérification de chaîne sur cette page est désormais bornée à une fenêtre et dit franchement ce
qu'une fenêtre peut et ne peut pas prouver.

**Et c'est testé contre des données.** Les tests de routes de conformité préexistants tournaient sur
une base vide : ils passaient avec n'importe quelle agrégation. `ComplianceTargetCountsTest` pose
des anomalies sur deux cibles et vérifie que chacune garde les siennes ; vérifié par mutation en
retirant le filtre d'état.

**Le défaut de nommage du jar trouvé à la passe précédente avait un rayon d'impact plus large que le
workflow qui l'a révélé.** `gradle.properties` fixe une version, donc `bootJar` émettait
`vectispire-core-0.9.0.jar` tandis que `Dockerfile`, `Dockerfile.agent` et `release.yml` copiaient
tous le nom sans version. Les images conteneur **et** le pipeline de release étaient cassés, et rien
ne l'a vu parce qu'**aucun job de CI ne construit d'image ni ne coupe de release**. Les deux tâches
`bootJar` épinglent désormais `archiveFileName`.

### Résiduel

| # | Constat | Note |
|:--:|---|---|
| **W1** | Le sommaire de conformité **n'est pas dans la campagne d'intégration sur quatre moteurs**. Il a été vérifié ici à la main sur PostgreSQL et MySQL ; MariaDB et SQLite-en-déploiement ne l'ont pas été. | Une projection groupée est exactement le genre de requête qui diverge par pilote. Un cas d'intégration rendrait le contrôle manuel inutile. |
| **W2** | `nightly.yml` **n'a toujours jamais tourné en CI** — impossible à déclencher d'ici. Ses étapes ont été exécutées en local et deux bloquants corrigés (nom du jar, `ddl-auto` SQLite), mais un workflow reste une hypothèse tant que le runner ne l'a pas exécuté. | Déclencher une fois en `workflow_dispatch`. |
| **W3** | **Aucun job de CI ne construit les images conteneur.** C'est pourquoi le défaut de nom de jar a survécu. | Un `docker build` sur les deux Dockerfiles l'aurait pris en une ligne de workflow. |

---

## 📋 5. Conformité Réglementaire & Standards — 9,3

Six référentiels — NIS 2, CRA UE, DORA, ISO/IEC 27001, PCI-DSS v4.0, OWASP — évalués par
`ComplianceEngine` dans le domaine pur, donc exhaustivement testables. Formats de chaîne
d'approvisionnement vérifiés présents : CycloneDX, SPDX, CSAF 2.0, OpenVEX, EPSS, reachability.

**Le moteur se mesure lui-même**, ce qui reste la propriété la plus distinctive du projet : un
contrôle est plafonné à `PARTIAL` quand la capacité qui le porte est éteinte, et le plafond
n'améliore jamais un contrôle en échec. Observé en direct pendant cette passe — une instance
démarrée localement sans miroir d'audit a scoré sa cible 60/100 au lieu d'afficher une conformité
qu'elle ne pouvait pas prouver.

**Et cet écart est désormais fermé pour le déploiement livré.** Le miroir d'audit est actif par
défaut en compose, écrit sur un volume nommé dont le propriétaire a été vérifié plutôt que supposé :
un volume monté sur un chemin que l'image ne possède pas arrive en `root`, chaque append échoue, et
le miroir est présent en configuration et absent en fait — pire que pas de miroir. Le Dockerfile crée
d'abord le répertoire au nom de l'utilisateur non privilégié.

---

## 🎯 6. Recommandations Priorisées

### 🟠 Ensuite
1. **Ajouter un `docker build` des deux images à la CI** *(W3)*. Le défaut de nom de jar a cassé
   l'image et la release pendant une durée inconnue et a été trouvé par accident. Un job ferme cette
   classe entière.
2. **Exécuter `nightly.yml` une fois en `workflow_dispatch`** et corriger ce que le runner révèle
   *(W2)*.
3. **Couvrir le sommaire de conformité dans la campagne d'intégration** pour que la projection
   groupée soit exercée sur les quatre moteurs plutôt qu'à la main sur deux *(W1)*.

### 🟡 Plus tard
4. **Retirer `VECTISPIRE_DB_DIALECT` de `TECHNICAL_DOCUMENTATION`, ou l'implémenter.** Les deux
   langues le documentent comme acceptant quatre moteurs ; il n'est référencé dans aucun code ni
   aucun fichier de configuration. Reporté de la passe précédente, toujours ouvert.
5. **Réconcilier le moteur par défaut.** `application.yaml` défaute la source de données sur
   PostgreSQL, la documentation dit PostgreSQL, et `docker-compose.yml` livre MySQL. Les trois sont
   défendables ; les trois ensemble sont une question qu'un exploitant ne devrait pas avoir à
   trancher.
6. **Énoncer précisément la frontière d'identifiants de l'agent** dans la documentation
   d'architecture — clés de déploiement scellées en mode délégué, jamais la clé de chiffrement,
   jamais la base.
7. **Décider si le second moteur de secrets doit exister.** Il est sauté par défaut désormais, il ne
   coûte donc rien ; mais une couture que personne n'utilise est une couture que personne ne
   maintient.

---

## 7. Conclusion

Quatre passes en une journée, c'est inhabituel, et la trajectoire mérite d'être nommée. La première
a trouvé des contrôles correctement conçus et incorrectement câblés. La deuxième a trouvé deux
défauts introduits par la réparation elle-même. La troisième est allée sur un terrain que les deux
premières n'avaient pas couvert et y a trouvé un chemin de perte silencieuse dans le traitement des
identifiants fuités. Celle-ci a exécuté le logiciel au lieu de le lire, et a établi que les
correctifs tiennent sur des moteurs que la campagne de tests ne touche jamais.

Chaque passe a trouvé moins, et l'a trouvé plus loin du centre. C'est à cela que ressemble une
convergence, et c'est l'argument de la méthode : **un audit qui ne fait que relire ses propres
conclusions mesure l'audit précédent.** Ce qui reste n'est pas architectural. C'est un job qui
construit une image, un workflow qui n'a jamais tourné, un réglage documenté qui n'existe pas, et un
moteur par défaut nommé différemment à trois endroits.

**9,1 / 10.**
