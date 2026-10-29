# 0046 — Les codes de conformité que 1.0 fige : ceux du CRA tel qu'adopté, l'édition 2021 d'OWASP

**Date :** 2026-10-29 · **Statut :** proposée · **S'appuie sur :** [0043](0043-what-1-0-promises.md) §6 · **Décideur :** Laurent Boucher

## Contexte

[0043](0043-what-1-0-promises.md) §6 demande que les codes de conformité soient fixés avant 1.0, parce que
1.0 les fige : après elle, renommer un code est un retrait annoncé deux versions mineures à l'avance, ou une
`/api/v2`. Deux ensembles sont en cause.

- **Les codes du CRA suivent la numérotation des articles de la proposition de 2022.**
  `ComplianceFramework.EU_CRA` porte `CRA-ART11-NOTIF`, `CRA-ART10-SBOM`, `CRA-ART10-LIFECYCLE` et
  `CRA-ART10-VULN`. Le règlement (UE) 2024/2847 tel qu'adopté a déplacé ces obligations : le signalement à
  l'art. 14, les obligations du fabricant à l'art. 13, les exigences de gestion des vulnérabilités à
  l'annexe I, partie II. Les titres citent déjà le texte adopté ; les codes ont été gardés exprès, parce
  qu'ils sont enregistrés avec chaque déclaration de contrôle (`ControlDeclarationEntity.controlCode`) et
  apparaissent dans l'API, le SARIF et le rapport PDF. Aujourd'hui, un auditeur lit donc `CRA-ART10-VULN` à
  côté de « Annexe I, partie II (2) ; art. 13(8) ».
- **Les catégories OWASP sont celles de l'édition 2021.** `OwaspTag` n'accepte que les étiquettes
  `A0n:2021` des jeux de règles, `OwaspCoverage.CATEGORIES` liste les titres de 2021, et l'enregistrement
  hebdomadaire de couverture stocke une catégorie par cible et par semaine. L'édition 2025 renumérote et
  remanie la liste (les défaillances de la chaîne d'approvisionnement et les conditions exceptionnelles
  entrent, la SSRF rejoint le contrôle d'accès) : une catégorie 2021 ne correspond pas une à une à une
  catégorie 2025.

## Décision

### 1. Les codes du CRA passent à la numérotation adoptée, une fois, avant 1.0

| Aujourd'hui | À partir de la mineure qui porte ce changement |
|---|---|
| `CRA-ART11-NOTIF` | `CRA-ART14-NOTIF` |
| `CRA-ART10-SBOM` | `CRA-ANNEX1-SBOM` |
| `CRA-ART10-LIFECYCLE` | `CRA-ART13-LIFECYCLE` |
| `CRA-ART10-VULN` | `CRA-ANNEX1-VULN` |

- **Chaque code nomme la disposition que son titre cite en premier.** Un code est ce qu'un auditeur
  rapproche du règlement, et un code qui pointe vers le mauvais article est une constatation dans l'audit
  qu'il devait faciliter.
- **Les déclarations enregistrées sont réécrites par une migration**, un `UPDATE` par code, et
  `ci/upgrade/accepted-rewrites.txt` de l'exercice de mise à niveau la liste avec cette décision pour
  raison.
- **Le changement d'API est une rupture, acceptée une fois.** `ci/openapi/accepted-breaks.txt` la liste ;
  les notes de version donnent le tableau ci-dessus. Elle a lieu maintenant, tant que 0.x le permet, plutôt
  que deux mineures après 1.0.
- **Les codes des autres référentiels restent.** L'art. 21 de NIS 2, l'annexe A d'ISO 27001:2022, les
  articles de DORA, les exigences de PCI DSS v4.0 et les critères de SOC 2 correspondent aux textes que
  citent leurs titres.

### 2. OWASP reste sur l'édition 2021 pour 1.0 ; 2025 viendra ensuite, à côté

- **1.0 fige les identifiants 2021** (`A01`…`A10` avec les titres de 2021) dans l'API et dans
  l'enregistrement hebdomadaire. Les jeux de règles en usage sont étiquetés avec l'édition 2021, et les
  questionnaires d'audit auxquels répond la page de couverture la demandent encore.
- **L'édition 2025 arrive dans une mineure 1.x, en ajout** : un second champ ou une seconde vue à côté de
  celle de 2021, à partir d'une correspondance qui dit où une catégorie 2021 se scinde ou se fond. L'ajout
  est permis par [0043](0043-what-1-0-promises.md) §1 ; le remplacement ne le serait pas.
- Rien à faire avant 1.0, sinon le dire sur la page de couverture et dans le guide de conformité :
  « OWASP Top 10, édition 2021 ».

## Conséquences

- Une version mineure (0.12 ou 0.13) porte une migration qui réécrit les codes CRA enregistrés, une rupture
  d'API acceptée et une note de version avec le tableau. Son estimation dans le plan 1.0 est de deux à trois
  jours.
- Un pipeline ou un modèle de rapport qui compare un code CRA change une fois. Celui qui compare une
  catégorie OWASP ne change pas à 1.0.
- Les documents qui listent les codes (`docs/{en,fr}/COMPLIANCE_AND_REGULATORY*.md`, le guide de conformité
  de `docs-site/`) changent dans la même pull request.

## Écarté

- **Garder les codes de 2022 comme identifiants opaques.** C'est ce que fait le code aujourd'hui, et cela ne
  coûterait rien. Cela laisse aussi chaque auditeur découvrir que `ART10` veut dire art. 13 et annexe I, et
  1.0 le rendrait définitif.
- **Passer OWASP à 2025 avant 1.0.** Les jeux de règles en usage ne portent pas d'étiquettes 2025 : la
  couverture tomberait à ce qu'une correspondance aurait deviné, et l'historique hebdomadaire changerait de
  sens en cours de route.
- **Des codes sans numéro d'article** (`CRA-NOTIF`). Stables quelle que soit la renumérotation, et inutiles à
  un auditeur qui les rapproche du texte.
