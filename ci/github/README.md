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

**Les douze jobs de `verify` sont requis, les conditionnels compris.** Les noms sont ceux des
identifiants de job, aucun ne portant de `name:` — s'ils changent dans `.github/workflows/ci.yml`,
ce fichier devient faux en silence et la protection s'affaiblit sans que rien ne le dise.

**Un job ignoré est traité comme satisfait, et ce dépôt l'a observé.** Le 17 septembre 2026, avec
la règle active et `e2e` requis, un commit ne touchant que `ci/` a laissé `e2e` ignoré et
la poussée de `main` est passée. C'est la question que ce fichier laissait ouverte depuis le
2 septembre ; elle est close par une observation et non par une lecture de documentation.

C'est ce qui permet d'exiger les deux jobs conditionnels. `e2e` a échoué du 15 au 17 septembre sans
que personne ne le lise, **parce qu'il ne bloquait rien** : trois boutons de la barre du haut sans
nom accessible, dont la déconnexion, écrits en toutes lettres dans chaque log. Un contrôle qui
n'engage à rien finit par ne plus rien dire, et c'est la seule raison pour laquelle ce défaut a
duré deux jours. `engines` est ajouté par le même raisonnement : quatre exécutions, quatre succès,
aucun échec — il passe quand il s'exécute.

## La règle absente, et c'est une décision

**Si un jour un job conditionnel se met à bloquer**, le remède n'est pas de le retirer des contrôles
requis mais d'ajouter un job-relais qui s'exécute toujours et rapporte le verdict du conditionnel :
vert s'il a passé, vert s'il n'avait pas lieu d'être, rouge s'il a échoué. C'est lui qu'on rend
requis. L'observation du 17 septembre dit que ce n'est pas nécessaire aujourd'hui.

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
