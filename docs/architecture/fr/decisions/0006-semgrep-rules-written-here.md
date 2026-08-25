# 0006 — Les règles de l'analyseur viennent d'ici, jamais de la cible

**Date :** 2026-08-11 · **Statut :** accepté

## Contexte

Deux des scanners lisent leur configuration dans l'arbre qu'ils analysent quand rien ne leur dit le
contraire, et cet arbre est écrit par celui qui est audité :

* **gitleaks** se rabat sur le `.gitleaks.toml` du dépôt analysé, et l'utilise *à la place* de ses
  règles intégrées. Une configuration vide avec une liste d'autorisation universelle éteint
  entièrement la détection : sortie 0, rapport vide, liste vide.
* **Semgrep** honore le `.gitignore` de l'arbre analysé. Un `*` commité exclut tout, et l'exécution
  signale un succès sur rien.

Aucun des deux ne produit d'erreur. Tous deux produisent la forme que la
[0007](0007-none-is-not-an-empty-list.md) désigne comme la plus coûteuse — une liste vide, qui
signifie « analysé, rien trouvé » et qui **résout** les anomalies ouvertes de ce type. Un dépôt
souhaitant faire disparaître ses constats pourrait les fermer lui-même, et la piste d'audit
enregistrerait une analyse propre.

Les jeux de règles eux-mêmes sont une seconde contrainte, sans rapport : les règles du registre
Semgrep amont ne peuvent pas être redistribuées sous la licence de ce projet, et une analyse qui les
tire à l'exécution n'est ni hors-ligne ni reproductible.

## Décision

**La configuration est toujours passée explicitement**, de sorte que celle de la cible n'est jamais
consultée : `--config` pour gitleaks comme pour Semgrep, `--no-git-ignore` pour Semgrep.

**Vectispire livre ses propres règles**, copiées dans l'espace de travail de l'analyse par
[`RulePlacement`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/RulePlacement.java),
et fusionne un répertoire fourni par l'exploitant via `VECTISPIRE_SEMGREP_RULES_DIR`.

## Conséquences

**Les règles sont copiées dans l'espace de travail plutôt que montées depuis l'image.**
Contre-intuitif, et obligatoire : les chemins de volume sont résolus par le *démon* Docker et non
par le processus qui l'appelle, donc un répertoire situé dans l'image de Vectispire est invisible
pour le conteneur de scan voisin. L'espace de travail est le seul chemin que les deux côtés voient —
en local comme sur un agent distant.

**Les règles sont placées avant l'exécution des scanners, pas à l'intérieur de l'étape SAST.** Le
scanner de secrets en a besoin aussi. Ne les copier que pour l'analyseur de source laissait gitleaks
lire la configuration de la cible, ce qui est exactement le défaut que cette décision existe pour
empêcher — et il était présent après sa première version.

**C'est l'atténuation que nomme le modèle de menaces.** L'entrée STRIDE *Tampering* de l'espace de
travail pointe ici : une configuration imposée côté serveur est ce qui empêche un dépôt analysé de
décider de ce qu'on cherche en lui.

**Ce qu'un exploitant peut encore faire.** `VECTISPIRE_SEMGREP_RULES_DIR` fusionne ses règles avec
le jeu livré — un ajout fait par le déploiement, pas par l'arbre audité. La distinction est toute la
décision : les règles viennent de quelqu'un qui n'est pas le sujet de l'analyse.

**Un jeu de règles impossible à obtenir fait échouer SAST seul**, et laisse son résultat absent
plutôt que de laisser l'analyseur tourner avec les règles livrées et rendre une liste propre et plus
courte. Même principe que ci-dessus, appliqué un cran plus bas.
