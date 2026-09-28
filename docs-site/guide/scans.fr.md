# Scans

Un scan est une exécution du pipeline contre une cible, par un agent.

## Le pipeline

Le pipeline est coupé selon une ligne unique : **l'exécuteur lance les scanners et ne touche
jamais la base de données ; l'ingesteur lit ses résultats et n'exécute jamais de conteneur.**
C'est ce qui permet à un code identique de tourner dans le plan de contrôle ou sur un agent
distant qui ne détient aucun identifiant de base de données.

1. **Cloner ou mettre à jour** la cible dans un répertoire de travail temporaire.
2. **Cataloguer** avec Syft, ce qui produit le SBOM.
3. **Rapprocher** les vulnérabilités connues avec Grype.
4. **Secrets** avec gitleaks, en double moteur avec déduplication automatique.
5. **IaC** avec checkov, pour Terraform et Kubernetes.
6. **Code source** avec Semgrep, si activé — voir
   [Jeux de règles Semgrep](../administration/rule-sets.md).
7. **Normaliser** l'ensemble en lignes `Finding`, enrichir avec EPSS et KEV, évaluer la liste
   de blocage de licences, contrôler la fin de support, et réconcilier avec les issues
   existantes.

Les étapes 2 à 6 s'exécutent dans des conteneurs éphémères avec **le réseau désactivé**, un
montage en lecture seule, `cap_drop: ALL` et `no-new-privileges`. Chaque image est épinglée par
empreinte.

Le seul appel sortant d'un scan est le catalogue de fin de support, qui transporte des noms de
produits et des versions — fait avant l'écriture des résultats du scan, jamais pendant. Les scores
EPSS et le statut KEV sont lus dans le fichier quotidien du FIRST et le catalogue de la CISA, que le
plan de contrôle synchronise en entier, si bien qu'aucun tiers n'apprend quelles CVE porte un dépôt. Le code analysé ne quitte pas la machine.

## Lire un scan

Le détail d'un scan montre ce qui a été trouvé et, plus utile, ce qui a **changé** : les issues
nouvelles, les issues désormais résolues. Sur un dépôt analysé chaque nuit, le total courant
bouge à peine, et le delta est toute la nouvelle.

Les sorties brutes sont conservées à côté des constats normalisés — le SBOM tel que le
catalogueur l'a produit, et la sortie brute du moteur de rapprochement — à fin d'audit. C'est
ce que vous remettez à quelqu'un qui veut re-dériver vos conclusions plutôt que les prendre
pour argent comptant.

Une carte **Ce que ce scan a examiné** dit quelles étapes intégrées ont regardé l'arbre :
vulnérabilités, secrets, IaC, analyse du code (sécurité et qualité ensemble), fin de vie, licences.
Une étape rangée sous **Examiné** a produit — un type sans constat dans ce scan a été recherché et
non trouvé, et ses issues ouvertes sur la cible ont été résolues. Une étape sous **Non examiné** n'a
pas regardé — elle a échoué (le message du scan dit laquelle et pourquoi), ou ce scan ne la lance
pas, comme une analyse d'image ne lance ni IaC ni analyse du code — et ses issues sont restées en
l'état. Un scan antérieur à cet enregistrement affiche **Non enregistré** plutôt que de montrer
chaque étape comme non examinée : rien n'a noté ce qu'il a regardé, et le prochain scan de la cible
l'enregistre. C'est ce même enregistrement qu'une checklist lit pour dire qu'un dépôt a été examiné :
une étape en échec ne compte jamais comme une étape passée sans constat.

Quand des [plugins](../administration/plugins.md) ont tourné, une carte **Plugins** liste chacun dans
l'un de trois états, dessinés distinctement : **produit** (vert, avec le nombre de constats de son
rapport), **non applicable** (gris — aucun de ses langages n'est dans l'arbre ; pas un échec) et
**absent — échec** (rouge, avec la raison). Seul le dernier est le problème de quelqu'un.

## Un scan qui n'a pas pu s'exécuter

Un scan qui s'arrête avant qu'un résultat existe — le clonage refusé, l'identifiant de la tâche
inutilisable, le réseau coupé — n'est pas retenté à l'aveugle. **Un échec qu'une autre tentative
rencontrerait de nouveau fait échouer le scan aussitôt**, avec la raison : une clé d'hôte qui a changé,
une authentification refusée, un dépôt, une branche ou un sous-chemin qui n'existe pas, une URL que le
clonage refuse. **Tout le reste attend puis réessaie** : le scan revient dans la file, *En attente*, et
ne peut pas être réclamé de nouveau avant une minute après sa première tentative, cinq après la
deuxième — sa page indique *la suivante peut démarrer à …* — et échoue pour de bon à la troisième. Il en
va de même que le worker intégré ou un agent l'ait exécuté. Voir
[Agents](../administration/agents.md#quand-une-analyse-ne-peut-pas-sexecuter-sur-un-agent) pour la façon
dont la nature de l'échec est décidée.

Ce n'est pas une étape qui a échoué dans un scan qui s'est exécuté : celle-là laisse ses propres
résultats absents, les autres tiennent, et le scan dit laquelle c'était.

## Un scan échoué n'est pas un scan propre

Un scan qui a échoué ne produit aucun constat, et une cible sans constat passe toutes les
politiques. La [vue d'ensemble Sécurité](dashboard.md) nomme cet état explicitement pour cette
raison. Vérifiez-le avant de lire un tableau de bord vert comme une bonne nouvelle.

Les causes fréquentes sont dans la [FAQ](../reference/faq.md).

## Où il a tourné

Chaque scan enregistre son agent. Sur une installation mono-machine, c'est toujours l'agent
intégré — le processus web lui-même, créé automatiquement au démarrage, ce qui est pourquoi une
installation fonctionne sans aucune configuration d'agent.

Un résultat produit sur un agent distant est indiscernable d'un résultat local : mêmes lignes,
même enrichissement, même politique, même réconciliation. Voir
[Agents](../administration/agents.md).
