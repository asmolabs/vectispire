# Architecture de Vectispire (Français)

Ce dossier est rédigé pour **quiconque reprend le code** — pas pour un réviseur, pas pour un comité. Il répond à trois questions, dans cet ordre : comment il est construit, pourquoi il est construit ainsi, et ce qui casse si vous le modifiez sans le savoir.

> Ces documents décrivent le système tel qu'il est : un plan de contrôle Spring Boot dans `vectispire-java/` et une interface Angular dans `vectispire-angular/`.

| Document | La question à laquelle il répond |
|---|---|
| [01 — Vue d'ensemble](01-overview.md) | Que fait Vectispire, de quoi est-il composé, et quel chemin emprunte un scan ? |
| [02 — Modèle de données](02-data-model.md) | Qu'est-ce qui est stocké, et pourquoi une *finding* n'est-elle pas une *issue* ? |
| [03 — Sécurité](03-security.md) | Quelles sont les frontières de confiance, qui les protège, et que reste-t-il à traiter ? |
| [04 — Exécution et déploiement](04-runtime-and-deployment.md) | Une instance, plusieurs, agents distants : qu'est-ce qui est autorisé et refusé ? |
| [Registre des décisions d'architecture (ADR)](decisions/README.md) | Une page par décision structurelle, avec l'alternative rejetée. |

Trois autres corpus vivent à côté de ces chapitres, et se rejoignent depuis cette page plutôt que
depuis le seul répertoire parent — un lecteur qui entre ici ne devrait pas avoir à deviner qu'ils
existent.

| Où | Ce que c'est |
|---|---|
| [Modèle de menaces STRIDE](../security/fr/STRIDE_THREAT_MODEL.fr.md) | L'analyse formelle derrière le [03](03-security.md) : une passe par catégorie STRIDE, avec le contrôle qui y répond. |
| [Modèle C4](../c4/README.md) | Le système en Structurizr DSL, avec les diagrammes de contexte, de conteneurs et de composants générés. La CI échoue si les diagrammes commités divergent de [`workspace.dsl`](../c4/workspace.dsl). |
| [Dossier d'architecture](../bflorat/fr/README.md) | Les cinq vues du modèle Bertrand Florat — applicative, sécurité, dimensionnement, infrastructure, développement. |
| [Modélisation des Menaces STRIDE](../security/fr/STRIDE_THREAT_MODEL.fr.md) | Analyse formelle des menaces selon les 6 catégories STRIDE. |
| [Diagrammes C4 (Structurizr DSL)](../c4/workspace.dsl) | Modélisation C4 interactive (Niveaux 1, 2 et 3). |

- [`docs/fr/GETTING_STARTED.fr.md`](../../fr/GETTING_STARTED.fr.md) — installation et exécution.
- [`docs/fr/TECHNICAL_DOCUMENTATION.fr.md`](../../fr/TECHNICAL_DOCUMENTATION.fr.md) — référence des modules et paramètres.
- [`docs/fr/ROTATION_AND_PURGE.fr.md`](../../fr/ROTATION_AND_PURGE.fr.md) — rotation des clés et purge des données brutes.
- [`docs/fr/api/rest_api_reference.md`](../../fr/api/rest_api_reference.md) — référence complète des endpoints REST.
- [`docs/fr/CI_CD_INTEGRATION.fr.md`](../../fr/CI_CD_INTEGRATION.fr.md) — guide d'intégration CI/CD et outil CLI (vectispire-cli).
- [`docs/fr/TICKETING_INTEGRATION.fr.md`](../../fr/TICKETING_INTEGRATION.fr.md) — synchronisation bidirectionnelle du ticketing (Jira, GitLab, GitHub, ServiceNow).
- [`docs/fr/NOTIFICATIONS_INTEGRATION.fr.md`](../../fr/NOTIFICATIONS_INTEGRATION.fr.md) — intégration des alertes et webhooks (Discord, Slack, Microsoft Teams).
