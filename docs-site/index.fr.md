# Vectispire

Vectispire suit la posture de sécurité du logiciel que vous livrez. Il analyse des dépôts Git
et des images de conteneur, génère un SBOM, y rapproche les vulnérabilités connues, détecte les
secrets écrits en dur, les licences problématiques et les erreurs de configuration
d'infrastructure, et centralise l'ensemble dans un seul tableau de bord.

Chaque scanner s'exécute dans un conteneur local éphémère, **réseau désactivé** et montage en
lecture seule. Rien du code que vous analysez ne quitte votre machine.

## Par où commencer

<div class="grid cards" markdown>

- **L'installer** — prérequis, base de données, premier compte, premier lancement.
  [Installation](getting-started/installation.md)

- **Analyser quelque chose** — enregistrer un dépôt, lancer un scan, le regarder aboutir.
  [Premier scan](getting-started/first-scan.md)

- **Comprendre ce qui revient** — constats, issues, gravité, et ce qui demande réellement une
  action.
  [Lire les résultats](getting-started/reading-results.md)

- **Faire échouer une construction dessus** — la barrière de politique, depuis un script shell
  ou un modèle de CI.
  [Barrière CI](integrations/ci-gate.md)

</div>

## Ce qu'il regarde

| Domaine | Scanner | Notes |
|---|---|---|
| Dépendances (SCA) | Syft → Grype | Génération du SBOM, puis rapprochement des vulnérabilités connues |
| Secrets | gitleaks | Clés d'API, jetons et identifiants commités dans le dépôt |
| Infrastructure as code | checkov | Erreurs de configuration Terraform et Kubernetes |
| Code source | Semgrep | Désactivé par défaut ; voir [Jeux de règles Semgrep](administration/rule-sets.md) |
| Fin de support | endoflife.date | Exécutions et distributions sorties du support de sécurité |
| Licences | depuis le SBOM | Évaluées contre une liste de blocage configurable |

Chaque image de scanner est épinglée par empreinte, pas par tag.

## Deux idées à lire d'abord

Deux distinctions traversent tout le produit, et l'essentiel des malentendus à son sujet vient
de leur confusion.

**Un constat n'est pas une issue.** Un *constat* est une observation, valable pour un scan. Une
*issue* est le même problème suivi d'un scan à l'autre — première apparition, nombre
d'occurrences, existence d'un correctif, décision prise à son sujet. L'empreinte de l'issue
ignore délibérément la version du paquet : une dépendance qui reste vulnérable sur trois
correctifs successifs garde un historique et une décision, au lieu de trois.

**L'état n'est pas le triage.** `state` (ouvert / résolu) n'est écrit que par le pipeline, à
partir de ce que les scanners observent. `triage_status` (le vocabulaire VEX : affecté, non
affecté, corrigé, en cours d'examen) n'est écrit que par une personne. Les deux sont tenus
strictement à part, parce qu'un constat supprimé et un constat réellement corrigé ne doivent
pas se ressembler.

[En savoir plus →](guide/issues.md)

## Obtenir de l'aide

- Quelque chose casse à l'installation : la [FAQ](reference/faq.md).
- Un problème de sécurité dans Vectispire lui-même : voir
  [SECURITY.md](https://github.com/asmolabs/vectispire/blob/main/SECURITY.md) pour la politique
  de divulgation — merci de ne pas ouvrir de ticket public.
