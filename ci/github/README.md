# Règle de protection de `main`

`main` est la branche par défaut : c'est celle depuis laquelle GitHub déclenche un workflow
planifié, et celle que prend qui clone le dépôt. Ce dossier contient la règle qui la protège,
sous une forme qu'on peut relire dans une revue.

**GitHub ne lit ce fichier nulle part.** Une protection de branche ne se déclare pas dans le
dépôt : elle vit dans la configuration côté forge et s'applique par l'API ou l'interface. Le
fichier est ici pour que la règle soit versionnée, discutée en diff, et réappliquée à l'identique
après un incident — pas parce qu'il agit.

## Appliquer

```sh
gh api --method POST /repos/asmolabs/vectispire/rulesets --input ci/github/main-ruleset.json
```

Mettre à jour une règle déjà en place, plutôt que d'en créer une seconde qui s'additionnerait :

```sh
gh api /repos/asmolabs/vectispire/rulesets --jq '.[] | "\(.id)\t\(.name)"'
gh api --method PUT /repos/asmolabs/vectispire/rulesets/<id> --input ci/github/main-ruleset.json
```

Vérifier ce qui s'applique réellement à la branche :

```sh
gh api /repos/asmolabs/vectispire/rules/branches/main
```

## Ce que la règle contient, et pourquoi

| Règle | Ce qu'elle empêche | Coût pour l'équipe |
|---|---|---|
| `deletion` | Supprimer `main` | Aucun |
| `non_fast_forward` | Réécrire l'historique par une poussée forcée | Aucun |
| `required_linear_history` | Un commit de fusion sur `main` | Aucun : `main` avance déjà en avance rapide depuis `develop` |
| `required_status_checks` | Avancer `main` sur un arbre que le pipeline n'a pas validé | Il faut attendre le pipeline |

Les dix contextes listés sont les jobs de `verify` qui s'exécutent **toujours**. Les noms sont
ceux des identifiants de job, aucun ne portant de `name:` — s'ils changent dans
`.github/workflows/ci.yml`, ce fichier devient faux en silence et la protection s'affaiblit sans
que rien ne le dise.

## Les deux règles absentes, et ce sont des décisions

**`engines` n'est pas dans les contrôles requis.** C'est le job qui exécute la campagne
multi-moteurs, et il est conditionnel : il est ignoré quand la modification ne touche pas
`db/migration/`. Exiger un contrôle qui n'apparaît pas toujours est le moyen classique de bloquer
une pull request définitivement, l'attente d'un contrôle qui ne viendra jamais n'ayant pas de fin.
GitHub traite en principe un job « ignoré » comme satisfait, mais **cela n'a pas été observé sur ce
dépôt** : à ajouter après avoir vu une pull request où `engines` est ignoré et constaté que la
fusion reste possible, pas avant.

**`pull_request` n'y est pas non plus, et c'est le vrai arbitrage.** L'ajouter interdirait la
poussée directe sur `main` — c'est-à-dire la façon dont cette branche a été mise à jour jusqu'ici,
en avance rapide depuis `develop`. C'est un changement de méthode de travail, pas un réglage. Pour
l'activer, ajouter aux `rules` :

```json
{
  "type": "pull_request",
  "parameters": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews_on_push": true,
    "require_code_owner_review": false,
    "require_last_push_approval": false,
    "required_review_thread_resolution": false
  }
}
```

Sur un dépôt à un seul mainteneur, `required_approving_review_count: 1` bloque tout : personne ne
peut approuver sa propre pull request. Mettre `0` conserve le passage obligé par une pull request
et l'attente des contrôles, sans exiger un second humain qui n'existe pas.

## Ce que cette règle ne règle pas

Elle protège `main` contre les mauvais changements. **Elle ne l'empêche pas de prendre du
retard** — et exiger une pull request pourrait même l'aggraver, en ajoutant une étape à la seule
opération qui la maintient à jour. Le retard de `main` a été traité ailleurs, en cessant d'en
dépendre : depuis le 2 septembre, la campagne moteurs s'exécute aussi dans `verify` dès qu'une
migration change, au lieu de n'exister que dans le nocturne.
