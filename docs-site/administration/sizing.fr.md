# Dimensionnement

Ce qu'un plan de contrôle demande pour le parc qu'il sert, d'après le premier test de charge, mené sur la
1.0.0-rc.1 : 300 cibles, 75 000 constats dont 60 000 ouverts, un million de lignes de composants, des
personnes, des pipelines et des agents au travail ensemble. Le rapport complet, avec chaque chiffre et la
façon de le rejouer, est dans le dépôt (`docs/analysis/fr/2026-10-30_test_de_charge_1.0.0-rc.1.fr.md`, et le
banc dans `load/`). Ce sont des valeurs de départ, mesurées sur une machine ; mesurez la vôtre.

## Ce qui limite

**Le CPU de la base, puis le tas du plan de contrôle.** Sur la base à quatre cœurs du test, les requêtes des
écrans les plus lents occupaient MySQL bien avant le plan de contrôle : à cinquante utilisateurs très actifs,
MySQL tenait ses quatre cœurs à plus de 80 % pendant que le plan de contrôle utilisait moins d'un cinquième
d'un cœur. Chaque requête attendait alors une connexion à la base, et toutes les routes ralentissaient
ensemble.

« Très actif » veut dire un écran par seconde et par personne, sans pause. Une personne au travail ouvre un
écran toutes les dix à trente secondes : les dix utilisateurs du test valent une centaine de personnes à
rythme humain, ses cinquante plusieurs centaines.

## Valeurs de départ

| Parc | Base de données | Plan de contrôle | Pool de connexions |
|---|---|---|---|
| Jusqu'à ~100 cibles, une équipe | 2 cœurs, 4 Gio, buffer pool 1 Gio | limite mémoire de 2 Gio (tas de 1,5 Gio) | 10 (la valeur par défaut) |
| ~300 cibles, 60 000 constats ouverts, ~100 personnes | **4 cœurs**, 8 Gio, buffer pool ≥ la taille des données | **limite de 2 à 3 Gio** (tas de 1,5 à 2,25 Gio) | 10 à 20 |
| Plusieurs centaines de personnes à la fois, ou davantage de cibles | 8 cœurs ou plus | limite de 4 à 5 Gio (tas de 3 à 4 Gio) | 20 à 30, avec les cœurs |

La ligne du milieu est celle mesurée ; la première et la dernière en sont tirées, sans avoir été testées.

- **Le tas** fait 75 % de la limite mémoire du conteneur dans l'image publiée (`MaxRAMPercentage=75`) : la
  limite par défaut de 2 Gio du chart Helm donne 1,5 Gio. Elle a tenu cinquante utilisateurs très actifs
  sur le parc du test ; à cent, le tas s'est rempli et la JVM a enchaîné des collections complètes. Relevez
  `resources.limits.memory` dans le chart, ou la mémoire du conteneur dans la composition.
- **Le pool de connexions** est celui de Hikari par défaut, dix, et aucun réglage livré ne le change. Dix
  connexions n'ont jamais été la limite sur quatre cœurs de base : ne l'augmentez qu'avec les cœurs de la
  base, car un pool plus grand donne aux mêmes cœurs davantage de requêtes à la fois. Il se règle par
  `SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE` (`spring.datasource.hikari.maximum-pool-size` de Spring), à
  garder sous le `max_connections` du serveur (151 par défaut).
- **Le buffer pool** : la composition livrée laisse à MySQL sa valeur par défaut de 128 Mio. Les données du
  parc de test pesaient 875 Mo ; donnez à InnoDB un buffer pool proche de la taille des données
  (`--innodb-buffer-pool-size`) pour que les lectures des écrans restent en mémoire.

## Ce que la base occupe

Mesuré sur le parc de test (875 Mo en tout) :

| Quoi | Taille |
|---|---|
| Un SBOM stocké | son document : 340 Ko dans le test, souvent 1 à 5 Mo pour le SBOM Syft d'une vraie image. La purge de rétention supprime les SBOM sortis de leur fenêtre (voir [Rotation et purge](maintenance.md)) |
| Une ligne de composant (un paquet d'un scan) | environ 0,3 Ko avec ses index ; le scan d'une image de 1 600 paquets ajoute 0,5 Mo. **Conservée** — l'historique de l'inventaire n'est pas purgé |
| Un constat | environ 1 Ko avec ses index |
| Une observation (un constat vu par un scan) | environ 0,35 Ko |
| Une décision de triage | environ 0,3 Ko |

Un parc de 300 cibles analysées chaque semaine, chaque scan d'environ 1 000 paquets, ajoute donc environ
300 × 52 × 0,3 Mo ≈ **4,7 Go par an de lignes de composants**, plus les SBOM dans leur fenêtre de rétention.
Prévoyez le volume, les sauvegardes et le buffer pool à partir de là.

## Scans et agents

Quatre agents ont rendu 300 résultats de scan de 420 Ko (1 600 composants et 200 vulnérabilités chacun) en
70 secondes — environ quatre résultats par seconde, 0,8 s chacun, quelque 15 000 par heure — pendant que dix
utilisateurs travaillaient sur les écrans. L'ingestion ne limite pas une installation de cette taille ; ce
sont les scanners des agents qui le font.

## Mettre à jour une installation existante vers la 1.0.0-rc.1

V96 et V98 reconstruisent `t_component` et `t_scan` une fois, au premier démarrage : 10 s ensemble sur le
million de lignes de composants et les 300 Mo de SBOM du parc de test. La durée croît avec l'inventaire et
les SBOM conservés ; le plan de contrôle ne répond à sa sonde de santé qu'une fois les migrations faites,
laissez donc de la marge à la sonde de démarrage (le chart accorde cinq minutes).
