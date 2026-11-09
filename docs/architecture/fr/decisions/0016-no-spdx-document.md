# 0016 — CycloneDX est le SBOM généré ; SPDX n'est pas produit

**Date :** 2026-08-25 · **Statut :** accepté · **Décideur :** Laurent Boucher

## Contexte

SPDX figurait parmi les formats de chaîne d'approvisionnement supportés dans quatre documents et
dans la description d'API de `GET /api/v1/scans/{id}/sbom`. L'audit du 25 août 2026 a établi
qu'**aucun document SPDX n'est produit nulle part**. Ce qui existe est SPDX comme *vocabulaire de
licences* : `Sbom` lit le champ `spdxExpression` d'un composant en repli de `value`. Il n'existe
aucun générateur SPDX à côté de ceux de CycloneDX, CSAF et VEX, et aucun `spdxVersion` ni `SPDXRef`
n'est écrit par le moindre chemin de code.

Le choix n'était donc pas « le garder ou l'abandonner » mais « le construire ou cesser de
l'annoncer », et trois faits ont tranché.

**Le document généré porte déjà ce que SPDX 2.3 ne sait pas exprimer.** Le point d'entrée CycloneDX
est `/api/v1/cyclonedx/scans/{scanId}/cyclonedx-vex.json` : le SBOM et les déclarations VEX dans un
seul document. SPDX 2.3 n'a aucun modèle de vulnérabilité — le profil sécurité arrive avec SPDX
3.0 — un export SPDX 2.3 serait donc le même inventaire, privé du triage. Le publier sous un second
nom reviendrait à livrer un document strictement moins informatif en appelant cela de la parité.

**Le point d'entrée brut n'est délibérément pas un document généré.**
`GET /api/v1/scans/{id}/sbom` sert, octet pour octet, ce que le cataloguer a produit, car un SBOM
passé par un analyseur puis par un rédacteur n'est plus ce que le cataloguer a validé.
`DependencyScanner` invoque Syft avec `-o json` : ce qui est servi est donc le format **natif** de
Syft — ni CycloneDX ni SPDX, quoi qu'en dise l'annotation.

**Un consommateur qui a besoin de SPDX a un chemin plus court que le nôtre.** Syft l'émet
directement (`-o spdx-json`) depuis l'image même que Vectispire épingle déjà. Le produire ici
coûterait une seconde exécution de conteneur par analyse, ou une seconde charge stockée par
analyse, pour rendre quelque chose que le consommateur peut générer lui-même depuis l'artefact
qu'il détient déjà.

## Décision

**CycloneDX 1.6 avec VEX intégré est le SBOM généré.** Les documents SPDX 2.3 ne sont pas produits,
et l'affirmation est retirée de la description d'API, des quatre documents qui la portaient et du
matériel de conformité.

Les **expressions de licence** SPDX continuent d'être analysées, car c'est une autre chose portant
le même nom : c'est ainsi que les composants déclarent leur licence, et l'abandonner casserait la
gouvernance des licences.

Le contrôle réglementaire n'est pas affecté et était déjà correct dans le code :
`CRA-ART10-SBOM` exige « un SBOM actif et lisible par machine » et ne nomme aucun format. Seul le
tableau de la documentation avait ajouté « (CycloneDX & SPDX) ».

## Conséquences

**Un intégrateur qui a besoin de SPDX doit convertir.** C'est un coût réel et il lui incombe. Il
est accepté parce que la conversion est une invocation de Syft sur un artefact qu'il détient déjà,
et parce que l'alternative était un second format de premier rang, sans triage dedans.

**La description d'API nomme désormais le JSON natif de Syft.** Une description qui promettait un
format que le point d'entrée n'a jamais servi est pire qu'une description sèche : c'est ce contre
quoi un intégrateur construit avant de découvrir que l'analyse échoue.

**Quand la réexaminer.** SPDX 3.0 change le calcul, car son profil sécurité peut porter les
déclarations VEX que la 2.3 ne peut pas — SPDX cesse alors d'être une copie appauvrie et devient
une vraie alternative. À réexaminer également si le processus d'achat d'un client exige SPDX
spécifiquement, ce qui est un fait commercial et non technique, et devrait être consigné comme tel.
