# 0006 — Les règles Semgrep sont écrites ici, pas redistribuées

**Date :** 2026-08-07 · **Statut :** acceptée

## Contexte

Le plan était d'embarquer un jeu de règles amont dans le dépôt, comme le sont les images
d'analyseurs : le scan reste hors ligne, et il est reproductible.

Ce plan est tombé sur une contrainte de licence découverte en cours de route.

- **`semgrep/semgrep-rules`** a été relicencié sous des termes qui **interdisent
  explicitement de distribuer les règles**. La vendorisation est donc impossible.
- **`opengrep/opengrep-rules`**, le fork pris avant ce changement, reste redistribuable —
  mais sous LGPL-2.1 **plus une Commons Clause**. Celle-ci ferait sortir Zanshin de l'open
  source au sens OSI et s'imposerait à tous ses reprenants.

## Décision

Trois sources, dans cet ordre.

**Les règles de Zanshin**, écrites ici, sans licence tierce : une quarantaine, Python /
JS-TS / Java, sécurité et qualité. Peu nombreuses et à fort signal.

**Un répertoire fourni par l'opérateur** (`ZANSHIN_SEMGREP_RULES_DIR`), fusionné avec le
précédent. C'est là qu'atterrissent les règles qu'il choisit.

**Un script de récupération** (`scripts/fetch_semgrep_rules.py`) qui va chercher
`opengrep-rules` à un tag épinglé, l'installe dans ce répertoire, affiche la licence et
écrit un manifeste. **Une fois, à l'installation, pas à chaque scan** : le scan reste hors
ligne et reproductible, et l'opérateur reçoit les règles de leur auteur sans que Zanshin
les redistribue.

## Ce qu'on a écarté

**Accepter la Commons Clause** pour obtenir un gros jeu de règles gratuitement. C'est un
mauvais prix : Zanshin cesserait d'être libre au sens OSI, et la restriction s'imposerait à
quiconque le reprend — pour des règles écrites par quelqu'un d'autre.

**Télécharger les règles à chaque scan** depuis le registre `semgrep.dev`. Le registre sert
aussi des règles propriétaires, ses conditions restreignent le téléchargement en masse, et
surtout un scan cesserait d'être reproductible et hors ligne — ce qui est la propriété
principale de cet outil.

## Conséquences

**Mettre à jour les règles est un déploiement, pas un bouton.** Conséquence assumée du
choix hors ligne, à écrire noir sur blanc dans les Paramètres.

**Construire une image d'agent contenant les règles récupérées est un usage propre ;
publier cette image serait une redistribution.** À dire dans la documentation, parce que
personne ne le devinera.

**Un jeu de règles qui ne contient pas de règles de qualité résoudrait tous les constats de
qualité** — les deux types entrent ensemble dans `scanned_types_for`. De même, recatégoriser
une règle chez l'amont détruit l'historique du problème, puisque le type entre dans
l'empreinte. Sans parade propre ; d'où le manifeste enregistré, pour qu'un mouvement de
masse ait au moins une explication.

**`--no-rewrite-rule-ids` est indispensable.** Avec un `--config` sur un répertoire,
Semgrep préfixe chaque `check_id` du chemin relatif de la règle : réorganiser `rules/`
renommerait donc chaque identifiant, ce qui **résoudrait tous les constats SAST et les
recréerait à neuf, triage perdu**.

**Les règles sont copiées dans l'espace de travail du scan.** Contre-intuitif mais
obligatoire : les chemins de volume sont résolus par le *démon* Docker, pas par le
processus Zanshin, donc un répertoire vivant dans l'image de Zanshin est invisible du
conteneur Semgrep frère.
