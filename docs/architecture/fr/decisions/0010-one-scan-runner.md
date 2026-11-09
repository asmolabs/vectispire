# 0010 — Un seul exécuteur de scan, et aucune couture autour

**Date :** 2026-08-17 · **Statut :** accepté · **Remplace :** [0001](0001-pluggable-scan-layer.md) · **Décideur :** Laurent Boucher

## Contexte

La conception NestJS que ceci remplace avait une interface `ScannerEngine` avec trois
implémentations : Docker, un mode binaire local, et un mode distant. Le portage n'en a repris
qu'une. Les deux autres n'ont pas été abandonnées par manque de temps — elles avaient cessé d'avoir
un sens :

* le mode **binaire local** exécutait les scanners sur l'hôte du control plane lui-même, avec le
  système de fichiers de l'hôte et sans aucun retrait de capacités, ce qui est l'inverse de ce que
  [`ContainerRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRunner.java)
  existe pour fournir ;
* le mode **distant** dupliquait, mal, ce que fait proprement un agent distant — un agent déplace
  l'exécuteur *entier* sur une autre machine plutôt que de relayer un appel de scanner à la fois.

Restait une interface avec une implémentation, la forme même qui invite à en inventer une seconde
plutôt qu'à en avoir besoin.

## Décision

Un seul `ScanRunner` concret, qui lance des conteneurs. L'interface n'est pas conservée « pour plus
tard ».

**L'exécution se déplace en lançant un agent ailleurs, pas en implémentant un autre moteur.** C'est
là qu'est la couture, et c'est une décision de déploiement plutôt que de code.

## Conséquences

**Une interface avec une seule implémentation est une affirmation que personne ne vérifie.** Elle
demande à chaque lecteur de tenir une généralité qui ne sert jamais, et elle rend la classe concrète
plus difficile à lire : les spécificités Docker — `cap_drop`, le rootfs en lecture seule, le tmpfs,
le réseau coupé, l'épinglage par digest — sont la partie intéressante, et elles ne peuvent pas
s'exprimer à travers une abstraction qui feint qu'elles pourraient ne pas s'appliquer.

**Ce que cela coûte.** Exécuter un scanner hors d'un conteneur devient une modification de
`ScanRunner` plutôt qu'une nouvelle classe. C'est la friction voulue : le conteneur est là où réside
l'isolation, et celui qui la retire devrait avoir à éditer le fichier qui le dit.

**Cette décision a servi de précédent, et c'est une charge qu'elle doit pouvoir porter.** La
[0015](0015-one-secrets-engine.md) a retiré un second moteur de secrets sur exactement ce
raisonnement — une couture avec une seule implémentation réelle et aucune couverture. Trancher cela
de façon cohérente est tout l'intérêt de l'avoir consigné.

**Quand réexaminer.** Quand une seconde implémentation est réellement exigée par quelque chose de
concret — pas quand on en imagine une. Un registre de moteurs de scan, chacun avec son gabarit
d'arguments et son fichier de règles, est une décision différente de la réintroduction d'une
interface, et il devrait remplacer cet enregistrement plutôt que s'y glisser dessous.
