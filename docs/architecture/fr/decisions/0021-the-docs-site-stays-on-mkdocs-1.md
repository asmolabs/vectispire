# 0021 — Le site de documentation reste sur MkDocs 1, jusqu'à ce qu'un autre outil sache le publier en deux langues

**Date :** 2026-09-24 · **Statut :** accepté · **Décideur :** Laurent Boucher

## Contexte

Le guide utilisateur de `docs-site/` est construit par MkDocs 1.6 avec Material for MkDocs et
`mkdocs-static-i18n`, et publié sur GitHub Pages par `docs.yml`. Il est **bilingue par
construction** : chaque page existe en `page.md` et `page.fr.md`, l'arbre anglais est servi à la
racine et l'arbre français sous `/fr/`, les textes de l'interface sont traduits par langue, et un
sélecteur passe de l'une à l'autre. Cette structure, c'est le plugin qui la fournit ; MkDocs lui-même
n'en fait rien.

MkDocs 2.0 supprime le système de plugins. Material for MkDocs est en maintenance, et le successeur
de son équipe est **Zensical**, qui lit `mkdocs.yml` et fait correspondre les plugins qu'il connaît
à ses propres modules. `mkdocs-static-i18n` s'est déclaré gelé pour la même raison.

La question n'était donc pas de savoir s'il faudrait quitter MkDocs 1 un jour, mais si Zensical
pouvait reprendre le site maintenant. On l'a **essayé plutôt que lu** : Zensical 0.0.64, sur une
copie inchangée de `mkdocs.yml`, `docs-site/` et `docs-site-overrides/`.

- Il a construit le site, vite, sans aucun changement de configuration.
- **Il a ignoré le plugin i18n.** Les pages françaises sont sorties à côté des anglaises —
  `/guide/repositories.fr/` à côté de `/guide/repositories/` — au lieu de former un arbre `/fr/` ;
  ni sélecteur de langue, ni interface en français.
- Les liens français entre pages ont été résolus contre les pages anglaises, d'où les trois ancres
  signalées manquantes : `#comment-la-note-du-scorecard-est-calculee` cherchée dans une page qui a
  `#how-the-scorecard-grade-is-computed`.

Sa page de compatibilité des plugins liste `search` et seize autres comme pris en charge et ne
mentionne pas `i18n` ; sa feuille de route cite les langues par suffixe et la traduction de
l'interface sous « publication à grande échelle », sans date, et dit explicitement qu'elle n'en
promet aucune.

## Décision

**Rester sur MkDocs 1.6, Material 9 et `mkdocs-static-i18n` 1.x, épinglés, et réévaluer quand un
successeur publie un site bilingue structuré par suffixe.**

L'épinglage est tenu à deux endroits, parce qu'un seul ne suffisait pas : `requirements.in` borne
`mkdocs<2`, mais `requirements.txt` est généré par `uv` sans l'en-tête que lit Dependabot, donc
`.github/dependabot.yml` refuse aussi explicitement une version majeure de MkDocs.

**Réévaluer quand** Zensical — ou un autre générateur — liste `mkdocs-static-i18n`, ou ses propres
langues par suffixe, comme pris en charge. Le test est celui mené ici : construire le site inchangé
et vérifier que `/fr/` existe, que le sélecteur fonctionne et que les trois ancres françaises se
résolvent.

## Ce qui a été écarté

**Migrer vers Zensical maintenant.** Cela aurait publié un site dont la moitié française est un
ensemble de pages orphelines sous des URL anglaises, avec l'interface en anglais — pire que le site
actuel, pour le bénéfice de quitter une version qui fonctionne encore.

**Migrer vers un autre générateur** (Docusaurus, Starlight). Les deux gèrent l'i18n, mais le site
serait réécrit — navigation, encadrés, surcharges Material, commentaires de `mkdocs.yml` qui portent
son raisonnement — pour échapper à un problème qui n'est pas encore arrivé : MkDocs 1.6 construit
toujours, est épinglé par empreinte, et ne change rien en restant immobile.

**Retirer le français du site.** Le produit documente des obligations réglementaires pour des
auditeurs francophones ; `AGENTS.md` fait des deux langues une exigence, pas une politesse.

## Conséquences

- MkDocs 1.6 ne recevra plus de versions. Une vulnérabilité dans MkDocs ou dans une dépendance
  épinglée devrait être jugée au regard de ce que fait le build — il lit le markdown de ce dépôt et
  rien d'autre — plutôt que corrigée par une montée de version.
- Le workflow `docs` construit désormais aussi sur `develop` et sur les pull requests : une montée de
  dépendance qui casse le build se voit avant `main`, pas au moment de la publication.
