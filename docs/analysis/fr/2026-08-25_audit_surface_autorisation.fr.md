# Audit approfondi — la surface d'autorisation, et ce que sa fermeture a cassé

**Date :** 2026-08-25 · **Périmètre :** les quatre axes du prompt · **Méthode :** affirmations
vérifiées en exécutant ; cette passe audite aussi les quatre correctifs posés depuis le rapport
précédent

## Notes

| Domaine | Note | Évolution | Ce qui a tranché |
|---|:--:|:--:|---|
| Documentation & Architecture | **9,2** / 10 | ↗ depuis 9,0 | Seize ADR, toutes argumentées ; le registre a absorbé une nouvelle décision sans couture. Rien ne vérifie encore un chiffre publié contre la constante qu'il nomme |
| Sécurité & Cryptographie | **8,0** / 10 | ↘ depuis 8,8 | Chaque contrôle nommé est réel, et Argon2id, SCIM, Vault et la chaîne d'audit se vérifient tous. **Vingt routes n'avaient aucune autorisation**, dont un contournement de privilège, et la note suit la découverte plutôt que la réparation |
| Qualité du Code & Architecture | **8,4** / 10 | ↗ depuis 7,8 | Lecteurs de tables entières passés de douze à cinq, chaque survivant justifié sur place. La scorecard conteneur a été oubliée dans son propre correctif, et rattrapée en rebalayant |
| Conformité Réglementaire | **8,8** / 10 | ↗ depuis 8,2 | SPDX tranché plutôt qu'abandonné ([0016](../../architecture/fr/decisions/0016-no-spdx-document.md)), le point d'entrée SBOM décrit ce qu'il sert, et le contrôle CRA n'a jamais sur-promis dans le code |
| **Global** | **8,6** / 10 | ↗ depuis 8,5 | |

**La note de sécurité baisse alors que la posture s'améliore, et c'est délibéré.** Vingt routes
acceptaient n'importe quel appelant authentifié ; elles sont corrigées, et la correction est
vérifiée par mutation. Mais une note est un énoncé sur ce que l'on sait, et ce que cette passe a
appris, c'est que la surface d'autorisation n'avait jamais été balayée — six audits l'ont notée sur
les contrôleurs qu'ils avaient lus. Redonner 8,8 reviendrait à dire que la faille n'a jamais
existé.

---

## 1. Documentation & Architecture — 9,2

Seize ADR, toutes porteuses de leur argument, et le registre a accueilli la nouvelle sans couture :
la [0016](../../architecture/fr/decisions/0016-no-spdx-document.md) consigne que CycloneDX avec VEX
intégré est le SBOM généré et que SPDX 2.3 n'est pas produit. Elle mérite d'être lue comme un
modèle de la forme que le registre s'impose désormais — elle nomme ce qui devrait changer pour que
la décision s'inverse (le profil sécurité de SPDX 3.0, ou l'exigence d'achat d'un client) et non
seulement ce qui a été choisi.

La parité bilingue tient : aucun orphelin d'un côté ni de l'autre, accord titre pour titre dans les
chapitres et les vues Florat, et le modèle C4 nomme toujours exactement les cinq images de scanner
épinglées.

**La lacune est inchangée et elle est de processus.** La CI contrôle les liens et la dérive C4.
Rien ne compare un nombre publié à la constante qu'il nomme — c'est ainsi que `2.0 vCPUs` a survécu
des semaines dans un document de sécurité sans qu'aucun code n'applique de limite CPU. Ce constat
est clos ; le mécanisme qui l'a permis ne l'est pas.

**Le prompt auquel cet audit répond est lui-même légèrement périmé**, et c'est l'instrument, donc
il faut le dire : il liste encore SPDX 2.3 parmi les formats supportés, que la
[0016](../../architecture/fr/decisions/0016-no-spdx-document.md) a retiré ; il affirme « aucune
socket Docker montée » là où la vérité est que les *scanners* n'en ont aucune tandis que le plan de
contrôle et l'agent en ont une — ce qui est toute la raison d'être du bac à sable ; et il nomme
`verifyIntegrity`, alors que la méthode s'appelle `verify()`.

---

## 2. Sécurité & Cryptographie — 8,0

### Ce qui se vérifie

| Contrôle | Vérifié comment |
|---|---|
| Argon2id | 19 Mio, t=2, format PHC — le minimum OWASP, les paramètres voyageant avec l'empreinte pour pouvoir être relevés sans invalider les mots de passe stockés |
| Bac à sable des scanners | `ContainerHardeningTest` capture le `HostConfig` remis au démon et vérifie `cap_drop ALL`, `no-new-privileges`, racine en lecture seule, mode réseau, mémoire, plafond PID **et la part CPU** — ajoutée cette semaine, après que le document en eut annoncé une pendant des semaines sans qu'aucun code ne l'applique |
| Isolation de l'agent | ArchUnit interdit JDBC, JPA, Spring Data, Flyway et Liquibase dans le module agent, avec un garde anti-import-vide |
| Chaîne d'audit | Deux suites **modifient une ligne stockée** et vérifient que la chaîne le signale |
| SCIM 2.0 | `@RequiresAdministrator` sur le contrôleur de provisionnement |
| KMS Vault | `VaultKmsProvider` existe, est testé, et `EncryptionService` **refuse de démarrer** si `kms.type=vault` est posé sans endpoint ni jeton — une mauvaise configuration qui se rabattrait silencieusement sur une clé locale serait le pire des deux mondes |
| Limitation de débit | Trois points d'entrée présentant des identifiants, seau par adresse, désormais configurable, et le limiteur par compte répond avec le même contrat `Retry-After` |

### Le constat : vingt routes ne demandaient jamais qui appelait

Parti du blast radius qui n'appliquait aucune `Visibility`, toute la surface des contrôleurs a été
balayée route par route. La documentation de `Visibility` dit elle-même que l'autorisation
dispersée dans neuf contrôleurs, c'est neuf occasions d'en oublier une, et que l'oubliée est le
trou. Elle avait été oubliée vingt fois, sous trois formes.

**Cinq laissaient un compte ordinaire modifier ou détruire l'état de la plateforme.** Elles
portaient `@RequiresAccount`, que tout compte connecté satisfait — `ROLE_USER` compris. La pire est
décrite par son propre résumé OpenAPI comme *« supprime atomiquement tous les endpoints et
contrats de toute la plateforme »*. Également accessible : l'ingestion d'un document VEX, qui dit
« non affecté » et fait donc taire des findings à l'échelle du parc — la décision même que le
workflow quatre-yeux rend délibérément coûteuse quand un humain la prend par l'interface.

**Six livraient des données rattachées à des cibles**, dont quatre qui exportent le *même scan* que
la route SBOM garde depuis toujours. Le format demandé décidait si le contrôle avait lieu.

**Huit agrégats répondaient à l'échelle du parc**, et l'un d'eux n'était pas une fuite de
visibilité mais un **contournement de privilège** : le bundle de preuves certifiées contient le
journal d'audit complet, et `/api/v1/audit-log` exige un responsable sécurité depuis toujours
tandis que le bundle n'exigeait qu'une session. La même donnée derrière deux portes avec deux
serrures différentes.

### Ce que la fermeture a cassé, et que cet audit a trouvé aussi

**L'interface proposait encore quatre commandes que le serveur refuse désormais.** L'import VEX et
l'export du bundle sur la page conformité, la synchronisation EPSS et le test de notification
étaient affichés pour tout compte, et aucune de ces pages ne consultait le rôle de la session. Un
bouton qui répond 403 dit au lecteur que le produit est cassé, pas que l'action ne lui appartient
pas.

Corrigé dans la même passe, avec le calcul `isSecurityLead` qui existait déjà dans `SessionStore`.
Les onze cas navigateur passent toujours. **C'est la forme de défaut qu'un correctif de sécurité
produit et qu'une revue de sécurité manque** : le serveur et l'interface étaient cohérents avant —
cohérents et faux — et durcir une moitié sans l'autre échange une vulnérabilité contre un défaut.

---

## 3. Qualité du Code & Architecture Logicielle — 8,4

**Lecteurs de tables entières : douze au précédent audit, cinq aujourd'hui**, et chaque survivant
est justifié là où il est.

| Restant | Pourquoi il reste |
|---|---|
| `GateService.openIssuesByTarget` | La vue d'ensemble sécurité montre toutes les cibles ; lire les anomalies de toutes les cibles *est* la question |
| `LicenseGovernanceService` ×2 | `@RequiresSecurityLead`, donc pas de fuite ; la lecture reste non bornée et c'est le prochain candidat |
| `ThreatIntelFeedService` | La synchronisation du flux réévalue le backlog par construction — une passe de maintenance, pas une lecture par appelant |

**Un a été oublié à l'intérieur de son propre correctif.** La scorecard dépôt a été cadrée et la
scorecard conteneur, vingt lignes plus bas, non. Relire le diff ne l'a pas attrapé ; rejouer le
balayage si. C'est l'argument pour balayer par motif plutôt que juger les sites d'appel un par un,
et il vaut pour celui qui a écrit le motif autant que pour quiconque.

La règle de couches, le contrat de retour des scanners imposé par réflexion, la campagne trois
moteurs et les planchers de couverture vérifiés par mutation tiennent tous. 1249 tests unitaires ;
vingt-quatre contrôleurs sur quarante et un résolvent désormais une `Visibility`, contre environ
treize ce matin.

**Le frontal est maintenant réellement couvert par ses E2E**, ce qui est nouveau : onze cas, tous
verts, exécutés en série parce qu'ils partagent un compte et une adresse avec les compteurs
anti-force-brute du serveur. Quinze specs unitaires Angular pour vingt-sept pages reste ténu.

---

## 4. Conformité Réglementaire & Standards — 8,8

Six référentiels — `NIS_2`, `ISO_27001`, `EU_CRA`, `DORA`, `PCI_DSS`, `SOC_2` — avec la posture de
la plateforme elle-même plafonnant la note qu'elle peut revendiquer : pas de clé de chiffrement
plafonne la gestion des secrets à 60, pas de miroir d'audit plafonne la journalisation à 70, pas de
quatre-yeux plafonne la gouvernance à 75. Le plafond ne fait que baisser.

**SPDX est désormais tranché plutôt que revendiqué en silence.** L'audit précédent l'avait trouvé
listé dans quatre documents et produit nulle part. La
[0016](../../architecture/fr/decisions/0016-no-spdx-document.md) consigne le raisonnement : SPDX
2.3 n'a aucun modèle de vulnérabilité, un export serait donc l'inventaire CycloneDX privé du
triage, sous un second nom. La description du point d'entrée SBOM nomme maintenant le JSON natif de
Syft, qui est ce qu'il a toujours servi.

CycloneDX, CSAF, OpenVEX, EPSS et l'atteignabilité sont réels, accessibles — **et désormais
cadrés**, ce qu'ils n'étaient pas : les trois exports `aggregate.json` nommaient chaque CVE de
chaque cible à n'importe quel compte.

---

## Recommandations

### 🔴 Maintenant

1. **Surveiller la première exécution nocturne.** `nightly.yml` n'a toujours jamais tourné sur un
   runner. La campagne trois moteurs, les deux images Dockerfile et les onze cas navigateur
   s'exécutent pour la première fois cette nuit, contre une semaine de changements. Vert en local
   n'est pas vert sur un runner froid.
2. **Faire relire les quatre routes nouvellement gardées par un œil neuf.** Elles ont été trouvées,
   modifiées et testées par la même personne, ce qui est le maillon faible de toute cette semaine.

### 🟠 Ensuite

3. **`LicenseGovernanceService`**, le dernier lecteur de table entière non justifié. Pas de fuite —
   le contrôleur exige un responsable sécurité — mais deux lectures complètes de `t_component` et
   `t_finding` sur une page.
4. **Rendre `fingerprint` unique**, avec une migration qui commence par rapporter les doublons
   qu'elle casserait. L'index est déjà là ; l'unicité est l'invariant.
5. **Vérifier les chiffres publiés contre les constantes qu'ils nomment.** Un test lisant
   `ScannerLimits.DEFAULT` et vérifiant que la vue dimensionnement le cite aurait attrapé
   `2.0 vCPUs` le jour où il est devenu faux — et tiendrait maintenant les chiffres corrigés
   honnêtes.

### 🟡 Puis

6. **Donner au frontal une couverture unitaire.** Quinze specs pour vingt-sept pages, les E2E
   portant la charge avec onze cas.
7. **Corriger `PROMPT_AUDIT.md`**, qui est l'instrument sur lequel ces audits tournent : SPDX est
   retiré, l'affirmation sur la socket Docker est imprécise, et `verifyIntegrity` s'appelle
   `verify()`.
8. **Envisager un test de couverture des routes** qui échoue lorsqu'un nouveau contrôleur servant
   des données rattachées à des cibles ne résout aucune `Visibility`. Le balayage en a trouvé
   vingt ; rien n'arrête la vingt-et-unième.
