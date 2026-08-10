# Architecture de Zanshin

Ce dossier s'adresse à **quelqu'un qui reprend le code** — pas à un évaluateur, pas à un
comité. Il répond à trois questions, dans cet ordre : comment c'est fait, pourquoi c'est
fait comme ça, et qu'est-ce qui casse si on y touche sans savoir.

| Document | La question à laquelle il répond |
|---|---|
| [01 — Vue d'ensemble](01-vue-d-ensemble.md) | Que fait Zanshin, de quoi est-il fait, et par où passe un scan ? |
| [02 — Modèle de données](02-modele-de-donnees.md) | Qu'est-ce qui est stocké, et pourquoi un *constat* n'est pas un *problème* ? |
| [03 — Sécurité](03-securite.md) | Quelles sont les frontières de confiance, ce qui les garde, et ce qui reste ouvert ? |
| [04 — Exécution et déploiement](04-execution-et-deploiement.md) | Une instance, plusieurs, des agents distants : qu'est-ce qui est permis et qu'est-ce qui est refusé ? |
| [Registre des décisions](decisions/) | Une page par décision structurante, avec l'alternative écartée. |

## Ce que ce dossier remplace

Deux fichiers nommés `ADR-001` et `ADR-002` qui avaient atteint 957 et 825 lignes. Ce
n'étaient plus des décisions mais des journaux de bord : sections `9bis`, `9ter`,
`9quater`… jusqu'à `9undecies`, chacune ajoutée après une vague de travail, aucune ne
remplaçant la précédente. Personne n'y aurait trouvé l'état courant du système sans lire
les 1 800 lignes et arbitrer soi-même entre ce qui restait vrai et ce qui avait été
dépassé.

La distinction que ce dossier tient, et que les deux fichiers avaient perdue :

- **La description est au présent.** Les documents 01 à 04 décrivent le système tel qu'il
  est. Ils sont réécrits quand il change, pas complétés.
- **Les décisions sont datées et immuables.** Une décision qui ne tient plus est
  *remplacée* par une autre qui la cite, jamais modifiée. C'est tout l'intérêt d'un ADR,
  et c'est exactement ce que les anciens fichiers ne faisaient pas.

Le contenu des deux fichiers a été repris avant leur suppression : les décisions dans le
registre, les leçons durement acquises — les six défauts de portabilité, les pièges de
concurrence mesurés, les impasses essayées — dans les documents et dans les commentaires
du code. `git log docs/architecture/` retrouve les originaux.

## Comment le garder honnête

Ce dossier ne vaut que s'il est vrai, et un document d'architecture faux est pire que pas
de document : il est cru. Trois règles suivies ici.

**Ce qui est vérifié par un test le dit et le référence.** Un dossier qui affirme
« l'agent ne touche jamais la base » sans dire que `tests/test_agent_worker.py` l'impose à
l'import énonce un vœu.

**Les limites connues sont écrites au même endroit que les garanties.** Une section
« reste ouvert » à la fin de chaque document, pas dans un fichier séparé que personne
n'ouvre. Un lecteur qui découvre une limite ailleurs cesse de croire le reste.

**Le détail d'implémentation reste dans le code.** Ce dossier explique *pourquoi* et
*comment les pièces s'agencent* ; le « comment exactement » est dans les docstrings, qui
sont au même endroit que ce qu'elles décrivent et vieillissent donc moins vite. Quand ce
dossier et un module se contredisent, **le module a raison** et ce dossier a un bug.

## Ailleurs dans la documentation

- [`docs/GETTING_STARTED.md`](../GETTING_STARTED.md) — installer et lancer.
- [`docs/TECHNICAL_DOCUMENTATION.md`](../TECHNICAL_DOCUMENTATION.md) — référence des
  modules, des réglages et des variables d'environnement.
- [`docs/ROTATION_ET_PURGE.md`](../ROTATION_ET_PURGE.md) — rotation de la clé de
  chiffrement et purge des données brutes.
