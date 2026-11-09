# Audit approfondi — le motif derrière deux défauts

**Date :** 2026-08-25 · **Périmètre :** documentation & architecture, sécurité & cryptographie,
qualité du code, conformité réglementaire · **Méthode :** affirmations vérifiées en exécutant, pas
en lisant

> **Sur le prompt auquel cet audit répond.** La copie qui l'a lancé est antérieure : elle demande
> les ADR 0001–0013 (il y en a quinze), nomme MariaDB et un second moteur de secrets (retirés par
> les [0014](../../architecture/fr/decisions/0014-two-engines-and-a-test-fixture.md) et
> [0015](../../architecture/fr/decisions/0015-one-secrets-engine.md)), et affirme qu'aucune socket
> Docker n'est montée — les *scanners* n'en ont aucune, le plan de contrôle et l'agent en ont une,
> et c'est toute la raison d'être du bac à sable. Le `PROMPT_AUDIT.md` du dépôt est à jour. Cet
> audit mesure le code, pas les hypothèses du prompt.

## Notes

| Domaine | Note | Évolution | Ce qui a tranché |
|---|:--:|:--:|---|
| Documentation & Architecture | **9,0** / 10 | ↘ depuis 9,4 | Le corpus est complet, bilingue et désormais vérifié contre le code — mais il aura fallu cette passe pour trouver onze affirmations du dossier Florat que le code ne soutenait pas, dont un contrôle de ressource inexistant |
| Sécurité & Cryptographie | **8,8** / 10 | ↘ depuis 9,3 | Chaque contrôle nommé est réel et la plupart sont testés en les cassant. Deux manques résiduels : aucun quota CPU sur les conteneurs de scan, et jusqu'à aujourd'hui deux limiteurs répondaient au même point d'entrée avec deux contrats différents |
| Qualité du Code & Architecture | **7,8** / 10 | ↘ depuis 9,1 | Le cloisonnement, le contrat de retour des scanners et la campagne trois moteurs sont exemplaires. **Sept points d'entrée HTTP chargent des tables entières en mémoire** — le défaut réparé deux fois aujourd'hui est systémique, pas accidentel |
| Conformité Réglementaire | **8,2** / 10 | ↘ depuis 9,0 | Six référentiels, CycloneDX, CSAF, OpenVEX, EPSS et l'analyse d'atteignabilité sont réels et accessibles. **Aucun document SPDX n'est jamais produit**, alors que la description d'API du point d'entrée SBOM en promet un |
| **Global** | **8,5** / 10 | ↘ depuis 9,2 | |

**Toutes les notes baissent, et c'est le constat plutôt qu'une régression.** Rien ne s'est dégradé
cette semaine ; cinq audits ont noté un terrain qu'ils avaient lu et non mesuré. Celui-ci a exécuté
les suites navigateur, piloté un vrai plan de contrôle, et balayé la couche service à la recherche
d'un motif au lieu de juger les services un par un — et le motif était là. Une note qui baisse
quand la mesure s'améliore, c'est la mesure qui fonctionne.

---

## 1. Documentation & Architecture — 9,0

### Ce qui tient

**La complétude structurelle est réelle.** Cinq vues Florat, un modèle C4 en Structurizr DSL avec
une tâche CI qui régénère les diagrammes et échoue sur dérive, un modèle STRIDE, quinze ADR — le
tout dans les deux langues, avec une parité titre pour titre (6/6, 5/5, 3/3, 7/7 sur les chapitres ;
8/8, 11/11, 7/7, 6/6, 9/9 sur les vues). `docs/fr` et `docs/en` n'ont d'orphelin ni d'un côté ni de
l'autre.

**Le modèle C4 est en phase avec le code.** Il nomme exactement les cinq images de scanner que
[`ScannerImages`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/scanners/ScannerImages.java)
épingle — syft, grype, gitleaks, checkov, semgrep — et décrit la base comme « PostgreSQL / MySQL
(Flyway Migrations) », ce qu'a décidé la
[0014](../../architecture/fr/decisions/0014-two-engines-and-a-test-fixture.md). Aucun MariaDB,
aucune revendication de quatre moteurs, aucun second moteur de secrets hors des enregistrements
remplacés.

**Les quinze ADR portent maintenant leur argument**, y compris les quatre courtes, qui disent ce
qui les a démenties — la partie qu'un successeur ne peut pas fournir, puisqu'un successeur plaide
sa propre cause. L'histoire des moteurs se lit de bout en bout et finit à un moteur de son point de
départ : le périmètre de la 0014 est exactement celui de la 0008.

### Ce que cette passe a trouvé

**Onze affirmations du dossier Florat que le code ne soutenait pas**, depuis corrigées. Trois
comptent plus que les autres :

* **Un contrôle qui n'existe pas.** La vue dimensionnement listait `Quota CPU : 2.0 vCPUs` par
  conteneur de scan et promettait des « quotas de mémoire et CPU imposés ».
  [`ContainerRunner`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRunner.java)
  pose la mémoire, une limite de PID et un timeout — et aucune limite CPU d'aucune sorte. Un
  opérateur qui dimensionnait sa machine sur ce chiffre dimensionnait sur rien. Les nombres voisins
  étaient faux aussi : 2 Go et non 1,5, 15 minutes et non 10, et le plafond de 512 PID — le
  contrôle qui, lui, existe — n'était pas mentionné.
* **Un mécanisme décrit à l'envers.** L'élection du leader était enseignée comme
  `SELECT … FOR UPDATE` sur `lease_name = 'SCHEDULER'`. La colonne s'appelle `name`, la valeur est
  en minuscules, et aucun `FOR UPDATE` n'est jamais émis : l'acquisition est un `UPDATE`
  conditionnel gardé sur le détenteur et l'expiration précédents — un compare-and-swap qui ne tient
  aucun verrou pendant la passe.
* **Une stratégie d'accès jamais construite.** Le tableau volumétrique annonçait une indexation sur
  `target_id`, `status`, `fingerprint`. Aucune de ces colonnes ne porte ce nom, et `t_issue` ne
  portait **aucun index**. Voir §3.

**Cinq commentaires de code nommaient Liquibase** là où le build utilise Flyway depuis la
[0013](../../architecture/fr/decisions/0013-flyway-multi-dialect-migrations.md). L'un des cinq
justifiait un choix de conception par un mécanisme propre à Liquibase, absent de ce build ; sa
justification a été retirée plutôt que traduite en un équivalent Flyway que personne n'avait testé.

**Le chapitre exécution affirmait que SQLite est déployable** — la seule chose que la
[0014](../../architecture/fr/decisions/0014-two-engines-and-a-test-fixture.md) établit qu'il n'est
pas — et que les purges de rétention et le relais outbox sont élus par bail. Seul le planificateur
l'est.

### Ce qui coûte encore un point

La documentation est désormais vérifiée, mais **rien ne la vérifie en continu.** La CI contrôle les
liens et la dérive C4 ; aucune tâche ne compare un chiffre publié à la constante qu'il nomme. C'est
ainsi que `2.0 vCPUs` a survécu : il n'a jamais été faux d'une manière qu'un build puisse voir.

---

## 2. Sécurité & Cryptographie — 8,8

### Des contrôles réels, testés en les cassant

| Contrôle | Où | Comment il est vérifié |
|---|---|---|
| Bac à sable des scanners | `ContainerRunner` | `cap_drop ALL`, `no-new-privileges`, racine en lecture seule, `network: none` sauf si un outil doit récupérer sa base, tmpfs pour `/tmp` et `/home/scanner`, plafond 512 PID, mémoire 2 Go — tous posés dans le code, aucun optionnel |
| Aucune socket dans un scanner | `DependencyScanner` | Seul le plan de contrôle parle au démon ; le cataloguer reçoit une archive exportée. Le commentaire en donne la raison : quiconque atteint la socket peut démarrer un conteneur privilégié |
| Isolation de l'agent | `AgentIsolationTest` | ArchUnit interdit `java.sql`, `jakarta.persistence`, `org.springframework.data`, `org.flywaydb` et `liquibase` dans le module agent, avec un garde anti-import-vide pour que la règle ne puisse pas passer à vide |
| Chaîne d'audit | `AuditLogDatabaseTest`, `AuditLogServiceTest` | Tous deux **modifient une ligne stockée** et vérifient que la chaîne le signale. Détection d'altération vérifiée en altérant, à deux niveaux |
| Miroir d'audit | défaut compose | Ferme le cas que la chaîne ne voit pas — supprimer la dernière entrée, dont rien ne descend, laisse une chaîne qui se vérifie parfaitement |
| Quatre yeux | chemin d'approbation | L'approbateur est comparé au **demandeur enregistré sur l'événement**, pas seulement à un rôle : un compte cumulant les deux rôles ne peut pas tenir les deux moitiés |
| Limitation de débit | `LoginRateLimitFilter` | Seau à jetons par adresse sur les trois points d'entrée qui présentent des identifiants, `X-Forwarded-For` honoré uniquement depuis les proxys de confiance configurés |

### Ce que cette passe a trouvé

**Deux limiteurs gardaient `/api/v1/auth/login` avec deux contrats différents.** Le filtre par
adresse a toujours renvoyé `Retry-After` ; le limiteur par compte
([`LoginThrottle`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/auth/LoginThrottle.java),
cinq tentatives ratées par utilisateur) renvoyait un 429 nu dont le délai n'était lisible qu'à
l'intérieur d'une phrase en anglais. Lequel des deux se déclenche dépend de si les tentatives
partagent une adresse ou un nom d'utilisateur — un client honorant l'en-tête, y compris l'écran de
connexion de cette application, recevait donc une information ou rien selon la manière dont on
l'attaquait. Réparé, avec un test qui vérifie que la valeur est un entier positif et pas seulement
qu'elle est présente.

**Un de mes diagnostics était faux et il est corrigé ici.** Huit des onze tests navigateur avaient
été rapportés comme un défaut applicatif — « un login renvoie 200 avec un jeton et laisse le
navigateur sur `/login` ». Piloter un vrai navigateur montre le login naviguant exactement comme
écrit. La page en échec disait `The server answered 429` : onze connexions en moins d'une minute
depuis une seule adresse constituent une rafale selon la seule définition dont le serveur dispose.
Les suites n'étaient pas indépendantes et faisaient comme si.

### Le manque résiduel

**Aucun quota CPU n'est appliqué aux conteneurs de scan.** Un scanner analysant une entrée hostile
peut saturer tous les cœurs pendant la durée de son timeout — quinze minutes. Le timeout borne la
durée ; rien ne borne la consommation. C'est désormais énoncé dans la vue dimensionnement plutôt
que contredit par elle, mais énoncer un manque n'est pas le combler.

---

## 3. Qualité du Code & Architecture Logicielle — 7,8

### Ce qui est exemplaire

**La règle de couches est appliquée et ne peut pas passer à vide.** `ArchitectureTest` vérifie six
couches avec un garde anti-import-vide explicite, et interdit au domaine d'importer Spring,
Hibernate, `java.sql` ou un client Docker.

**L'ADR 0007 est imposée par un type et vérifiée par réflexion.** `ScannerContractTest` identifie
les scanners lançant un conteneur par le fait qu'ils *détiennent* un `ContainerRunner` plutôt que
par leur nom : un scanner ajouté dans six mois est dans le périmètre dès qu'il existe. Ce test
existe parce que la faille était réelle et coûtait le type de finding le plus sensible : deux
scanners de secrets renvoyaient `List`, fusionnés dans un `catch (Exception ignored)`, et un échec
du second résolvait en silence toute fuite que lui seul détectait.

**La campagne moteurs s'exécute et est honnête sur ce qu'elle prouve.** Trois moteurs, 15
migrations par dialecte, 33 entités validées sous `ddl-auto: validate`, et une suite de parité qui
affirme une *borne inférieure* sur le nombre d'entités — parce qu'un nombre exact vérifie que
quelqu'un a mis à jour un littéral, ce qui est précisément la façon dont la campagne est restée
rouge en silence pendant une durée inconnue.

1229 tests unitaires, 9 suites d'intégration, des planchers de couverture cadrés par paquet et
vérifiés par mutation.

### Le constat : les lectures de tables entières sont systémiques

Deux ont été réparées aujourd'hui — `SecurityDebtService` et `GateService`. Balayer la couche
service à la recherche du motif, au lieu de juger les services un par un, en révèle **sept autres,
tous accessibles par HTTP** :

| Service | Point d'entrée | Ce qu'il charge |
|---|---|---|
| `BlastRadiusService` | `/api/v1/blast-radius` | **tous les findings et toutes les anomalies**, à deux reprises |
| `SecurityScorecardService` | `/api/v1/scorecard` | toutes les anomalies, deux fois ; tous les scans, deux fois |
| `EpssPrioritizationService` | `/api/v1/epss` | toutes les anomalies, puis filtre les ouvertes **en Java** |
| `EvidenceVaultService` | `/api/v1/compliance/...` | toutes les anomalies et tous les scans, filtrés en Java |
| `LicenseGovernanceService` | `/api/v1/licenses` | tous les composants et tous les findings |
| `CsafGeneratorService` | `/api/v1/csaf` | toutes les anomalies |
| `CycloneDxGeneratorService` | `/api/v1/cyclonedx` | toutes les anomalies |

`t_finding` est la table des constats bruts que la vue dimensionnement estime à **~500 000 lignes**.
La lire en entier pour servir une page n'est pas une requête lente ; c'est une réponse de la taille
du tas à une question de la taille d'un écran.

**Et jusqu'à cette semaine rien de tout cela n'était indexé.** `t_issue` ne portait aucun index —
le schéma en déclarait neuf et aucun ne portait sur la table que tous les chemins chauds lisent.
`(state, repo_id)`, `(state, container_id)` et `(fingerprint)` ont été ajoutés, et
`SchemaParityIntegrationTest` vérifie désormais leur existence sur chaque moteur via
`DatabaseMetaData`, de sorte qu'un refactoring ne peut plus les faire disparaître en silence.

**Pourquoi 7,8 et pas moins.** Le motif est uniforme, mécanique et désormais démontré deux fois —
chaque correction a demandé un test de caractérisation, un changement de requête et une
vérification par mutation. Rien là-dedans n'est architecturalement difficile. C'est une dette dont
la procédure de remboursement est connue, ce qui est une bien meilleure position qu'un défaut
subtil que personne ne sait localiser.

### Frontal

Quatre suites Playwright, onze cas, **tous verts** à la date de cet audit — et verts pour la
première fois, après que les suites ont cessé de se croire indépendantes. Quinze specs unitaires
Angular couvrent les pages de façon ténue. Les E2E sont la vraie couverture, et elles sont
désormais honnêtes : elles s'exécutent en série parce qu'elles partagent un compte et une adresse
avec les compteurs anti-force-brute du serveur.

---

## 4. Conformité Réglementaire & Standards — 8,2

### Ce qui est implémenté

**Six référentiels**, pas quatre : `NIS_2`, `ISO_27001`, `EU_CRA`, `DORA`, `PCI_DSS`, `SOC_2`
([`ComplianceFramework`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/compliance/ComplianceFramework.java)).
L'OWASP est présent comme surface de restitution propre — une page et un export PDF — plutôt que
comme référentiel de conformité, ce qui est la bonne modélisation : c'est une taxonomie de
vulnérabilités, pas une réglementation.

**Le score de conformité évalue la posture de la plateforme elle-même, pas seulement celle du
parc.** Un déploiement sans clé de chiffrement est plafonné à 60 sur la gestion des secrets, un
sans miroir d'audit à 70 sur la journalisation, un sans quatre yeux à 75 sur la gouvernance. Le
plafond ne fait que baisser, il ne peut donc pas flatter.

**CycloneDX, CSAF, OpenVEX, EPSS et l'atteignabilité sont réels et accessibles**, chacun avec un
service générateur et un contrôleur.

### Le constat : SPDX est revendiqué et n'est pas produit

`Spdx` apparaît dans six fichiers de sources principales, d'où l'impression qu'il est supporté. Ce
qui existe réellement :

* **Les *expressions* de licence SPDX sont analysées** — `Sbom.java` lit le champ `spdxExpression`
  d'un composant en repli de `value`. C'est SPDX comme vocabulaire de licences.
* **Aucun *document* SPDX n'est jamais généré.** Il existe un `CycloneDxGeneratorService`, un
  `CsafGeneratorService` et un `VexGeneratorService` ; il n'existe pas d'équivalent SPDX, et aucun
  `spdxVersion` ni `SPDXRef` n'est écrit nulle part dans le code.
* **La description d'API du point d'entrée SBOM est fausse.** `GET /api/v1/scans/{id}/sbom` est
  annoté « CycloneDX / SPDX SBOM JSON document ». Il sert, verbatim, ce que Syft a produit — et
  `DependencyScanner` invoque Syft avec `-o json`, soit le format **natif** de Syft, ni CycloneDX ni
  SPDX. Le document est correctement servi sans modification, pour la raison énoncée et bonne qu'un
  SBOM re-sérialisé n'est plus ce que le cataloguer a signé ; c'est la description de son contenu
  qui n'est simplement pas vraie.

Un consommateur qui lit la page OpenAPI et bâtit une ingestion SPDX contre ce point d'entrée reçoit
un format qu'il n'a pas demandé et qu'il ne sait pas analyser.

---

## Recommandations, dans l'ordre où je les prendrais

### 🔴 Maintenant

1. **Corriger la description d'API du point d'entrée SBOM** pour nommer le JSON natif de Syft. Une
   annotation, aucun changement de comportement, et cela évite qu'un intégrateur bâtisse contre une
   promesse. Puis décider, séparément et explicitement, si la sortie SPDX 2.3 est dans le périmètre
   — et si elle ne l'est pas, cesser de l'annoncer.
2. **Réparer `BlastRadiusService`.** C'est le pire des sept : deux lectures complètes de
   `t_finding` plus une de `t_issue`, sur une page. La procédure est établie — test de
   caractérisation, requête cadrée, vérification par mutation sur les lignes chargées.

### 🟠 Ensuite

3. **Traiter les six autres lecteurs de tables entières**, dans l'ordre du tableau du §3. Ils sont
   mécaniques ; l'intérêt est que le motif cesse d'être le style de la maison.
4. **Trancher la question du quota CPU.** Soit en appliquer un dans `ContainerRunner` — un scanner
   qui sature une machine est un déni de service livré par un dépôt hostile — soit consigner dans
   une ADR pourquoi le timeout est jugé suffisant. Les deux se défendent ; laisser la question
   ouverte, non.
5. **Rendre `fingerprint` unique**, avec une migration qui commence par rapporter les doublons
   qu'elle casserait. L'unicité est l'invariant réel et l'index est déjà là.

### 🟡 Puis

6. **Vérifier les chiffres publiés contre les constantes qu'ils nomment.** Un petit test qui lit
   `ScannerLimits.DEFAULT` et vérifie que la vue dimensionnement le cite aurait attrapé
   `2.0 vCPUs`, `1.5 GB` et `10 minutes` le jour où ils sont devenus faux.
7. **Surveiller la première exécution nocturne.** `nightly.yml` n'a jamais tourné sur un runner :
   la campagne trois moteurs, les deux images Dockerfile et les onze cas navigateur s'exécutent
   pour la première fois cette nuit. Vert en local n'est pas vert sur un runner froid.
8. **Donner au frontal une couverture unitaire.** Quinze specs pour vingt-sept pages laissent les
   E2E porter toute la charge, et onze cas, c'est peu pour ce qu'on leur demande de défendre.
