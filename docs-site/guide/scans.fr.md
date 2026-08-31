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

Les seuls appels sortants d'un scan sont les consultations EPSS et KEV, qui transportent des
identifiants CVE et rien d'autre, et le catalogue de fin de support, qui transporte des noms de
produits et des versions. Le code analysé ne quitte pas la machine.

## Lire un scan

Le détail d'un scan montre ce qui a été trouvé et, plus utile, ce qui a **changé** : les issues
nouvelles, les issues désormais résolues. Sur un dépôt analysé chaque nuit, le total courant
bouge à peine, et le delta est toute la nouvelle.

Les sorties brutes sont conservées à côté des constats normalisés — le SBOM tel que le
catalogueur l'a produit, et la sortie brute du moteur de rapprochement — à fin d'audit. C'est
ce que vous remettez à quelqu'un qui veut re-dériver vos conclusions plutôt que les prendre
pour argent comptant.

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
