# C4 model — Structurizr DSL / Modélisation C4 — Structurizr DSL

The system in [`workspace.dsl`](workspace.dsl), and the diagrams generated from it. **The
diagrams are generated, never drawn**: CI regenerates them from the model on every push and fails
if the committed files differ, so a picture cannot drift from the architecture it claims to show.

Le système décrit dans [`workspace.dsl`](workspace.dsl), et les diagrammes qui en sont issus. **Les
diagrammes sont générés, jamais dessinés** : la CI les régénère depuis le modèle à chaque poussée
et échoue si les fichiers commités diffèrent — une image ne peut donc pas diverger de
l'architecture qu'elle prétend montrer.

---

## Level 1 — System context / Niveau 1 — Contexte système

![C4 System Context Diagram](diagrams/structurizr-SystemContext.png)

## Level 2 — Containers / Niveau 2 — Conteneurs

![C4 Container Diagram](diagrams/structurizr-Containers.png)

## Level 3 — Backend components / Niveau 3 — Composants backend

![C4 Component Diagram](diagrams/structurizr-Components.png)

---

## Regenerating / Régénérer

Regenerate every diagram from the model — run this after any edit to `workspace.dsl`, because CI
compares the result against what is committed.

Régénérez tous les diagrammes depuis le modèle — à lancer après toute modification de
`workspace.dsl`, la CI comparant le résultat à ce qui est commité.

```bash
npm run c4:generate
```

Equivalently, [`scripts/generate-c4-diagrams.sh`](../../../scripts/generate-c4-diagrams.sh).
De façon équivalente, [`scripts/generate-c4-diagrams.sh`](../../../scripts/generate-c4-diagrams.sh).

## Browsing interactively / Explorer de façon interactive

Structurizr Lite serves the model as a navigable site, which is the comfortable way to move
between the three levels.

Structurizr Lite sert le modèle sous forme de site navigable, ce qui est la manière confortable de
circuler entre les trois niveaux.

```bash
docker run --rm -it -p 8080:8080 -v $(pwd)/docs/architecture/c4:/structurizr structurizr/lite
```

Then open `http://localhost:8080`. / Puis ouvrez `http://localhost:8080`.
