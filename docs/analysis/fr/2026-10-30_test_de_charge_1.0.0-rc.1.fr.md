# Test de charge de la 1.0.0-rc.1 (30 octobre 2026)

*Version anglaise : [2026-10-30_load_test_1.0.0-rc.1.en.md](../en/2026-10-30_load_test_1.0.0-rc.1.en.md)*

La liste de contrôle de la 1.0.0-rc.1 portait une ligne que personne n'avait mesurée : *quelques centaines
de cibles, des dizaines de milliers de constats*. Voici cette mesure : un parc semé de 300 cibles et
75 000 constats, un mélange scripté de ce qu'appellent les personnes, les pipelines et les agents, quatre
niveaux de concurrence, avant et après trois corrections. Le banc est dans
[`load/`](../../../load/README.md) et rejoue l'ensemble.

## En bref

- **Avant les corrections, le plan de contrôle ne tenait pas un parc de cette taille, à aucun niveau.**
  Deux appels de barrière par seconde venus des pipelines suffisaient : chaque verdict lisait tout
  l'inventaire des composants (1,65 s de MySQL, 390 000 lignes), les dix connexions à la base étaient
  tenues par la barrière, et toutes les autres routes attendaient derrière elle. Avec une seule personne au
  travail, une connexion prenait 47 s au p95 et le tableau de bord 25 s ; avec dix, un quart des connexions
  et un tiers des réclamations des agents expiraient.
- **Trois défauts, corrigés dans cette version** (V96 à V98) : la barrière et les tableaux de bord lisaient
  l'inventaire au lieu d'un index ; dix requêtes relisaient chaque SBOM stocké pour savoir si un scan en
  avait un ; l'historique des scans triait la table avec ses SBOM. Sans charge, la barrière est passée de
  1,85 s à 45 ms, le tableau de bord de 2,9 s à 0,5 s, le résumé des licences de 1,2 s à 20 ms.
- **Après les corrections, dix personnes très actives** (un écran par seconde chacune, environ onze
  requêtes par seconde avec les pipelines et les agents) **sont servies sans erreur, chaque écran sauf
  quatre sous 0,6 s au p95**, la barrière sous 0,1 s. Les quatre sont le tableau de bord (2,1 s), la
  recherche d'inventaire (1,0 s), la grille OWASP (1,0 s) et l'inventaire des licences (0,9 s) ; le
  résultat d'un scan est ingéré en 1,8 s au p95.
- **À cinquante personnes de ce rythme, le CPU de la base est la limite** — 330 % des quatre cœurs dont
  elle disposait — et chaque route attend une connexion : p95 entre 1,4 s et 12 s, toujours sans erreur.
  À cent, le tas de 1,5 Gio a atteint des collections complètes. Ce qui occupe ce CPU est connu et listé
  plus bas, avec ce que chaque point demanderait ; aucun n'était une correction ciblée.

## Environnement

| | |
|---|---|
| Machine | Apple M5, 10 cœurs, 32 Gio, macOS |
| Docker | Docker Desktop, une VM de **4 CPU et 8 Gio**, partagée par MySQL et le générateur de charge |
| Plan de contrôle | le jar de cette branche, sur l'hôte : JDK 25.0.4 (Temurin), `-Xms1536m -Xmx1536m`, G1 — la limite par défaut de 2 Gio du chart Helm à `MaxRAMPercentage=75` de l'image ; le pool Hikari par défaut de **10** connexions ; worker intégré coupé |
| Base de données | `mysql:9.4` (9.4.0), son propre conteneur et son propre volume ; les réglages de la composition livrée — ceux par défaut sauf `max-allowed-packet=160M`, donc un **buffer pool de 128 Mio** et 151 connexions ; journal des requêtes lentes à 200 ms |
| Générateur de charge | `grafana/k6:1.3.0` par empreinte, dans Docker, contre l'hôte |
| Limites levées | la limite des connexions (10 par minute et par adresse) et celle par clé (600 par minute), qu'un générateur sur une seule adresse mesurerait sinon |

MySQL 8.4 n'a pas été soumis à la charge ; la campagne d'intégration a passé les corrections sur 8.4 et 9.4.

## Le jeu de données

Semé par l'API, par `load/seed/seed.py`, en cinq minutes ; rien n'a été écrit en SQL. Les résultats des
scans sont arrivés par le protocole des agents : les constats, l'inventaire et les constats de licence ont
été écrits par l'ingestion qui les écrit en production.

| | |
|---|---|
| Cibles | 300 : 200 dépôts, 100 images, en six équipes |
| Comptes | 29 : un gouverneur, un administrateur, un RSSI, un champion sécurité, un auditeur, 24 lecteurs restreints |
| Scans | 907, trois par cible ; chaque tour après le premier change 8 % des constats et des composants de chaque cible |
| SBOM | 900 composants par dépôt, 1 600 par image, tirés de 12 000 paquets ; 340 Ko chacun, 300 Mo en tout |
| Constats | 75 585 (60 352 ouverts) : vulnérabilités, analyse de code, infrastructure, secrets, licences |
| Observations | 182 219 |
| Lignes de composants | 1 026 600 |
| Triage | 21 490 événements : un quart du stock ouvert décidé par lots, un cinquième de ceux-là décidé à nouveau |
| Base | 756 Mo avant les corrections, 875 Mo après les campagnes et les migrations |

## Le scénario

Quatre scénarios ont tourné ensemble pendant 90 s à chaque niveau (`load/k6/scenario.js`) :

- **Les personnes**, en modèle fermé : `N` utilisateurs virtuels, chacun ouvrant un écran, réfléchissant
  0,5 à 1,5 s, ouvrant le suivant. Deux tiers d'administrateurs ou de responsables — la liste des constats
  (première page, filtrée, recherchée, une page lointaine), un constat, un triage, le tableau de bord, les
  tendances, la vue d'ensemble de sécurité, les scorecards, l'analyse de posture, la recherche d'inventaire,
  les licences, la grille OWASP, la dette de remédiation, les scans, les cibles, l'export CSV d'une cible ;
  un tiers de lecteurs restreints — leur liste de constats, filtrée, un constat, le tableau de bord, leurs
  dépôts. **Un écran par seconde, c'est bien plus qu'une personne** : dix de ces utilisateurs valent plutôt
  une centaine de personnes au travail.
- **Les pipelines**, en modèle ouvert : deux appels de barrière par seconde (`POST /api/v1/gate`), avec des
  clés restreintes à leur dépôt.
- **Les connexions** : une toutes les deux secondes, chacune suivie d'une déconnexion.
- **Les scans** : un demandé toutes les cinq secondes ; quatre agents font du long polling (`wait=5`),
  réclament et rendent un résultat de 420 Ko (1 600 composants, 200 vulnérabilités), que le plan de
  contrôle ingère.

## Sans charge, un appel à la fois

`load/probe.sh`, troisième appel sur trois, sur le même parc :

| Route | Avant | Après |
|---|---|---|
| `POST /gate` | 1 892 ms | 38 ms |
| `GET /dashboard` (administrateur) | 2 870 ms | 449 ms |
| `GET /dashboard` (lecteur restreint) | 3 007 ms | 737 ms |
| `GET /security/overview` | 2 163 ms | 168 ms |
| `GET /scorecards/global` | 1 499 ms | 200 ms |
| `GET /dashboard/posture-analytics` | 1 593 ms | 271 ms |
| `GET /licenses/summary` | 1 491 ms | 18 ms |
| `GET /licenses/inventory` | 1 870 ms | 613 ms |
| `GET /owasp/coverage` | 785 ms | 371 ms |
| `GET /scans` | 789 ms | 109 ms |
| `GET /inventory/search` | 660 ms | 530 ms |
| `GET /issues` (première page, administrateur) | 162 ms | 135 ms |
| `GET /issues/{id}` | 18 ms | 43 ms |

Le premier appel de l'analyse de posture après un démarrage prend 5 s (à froid) ; les suivants sont ceux
du tableau.

## Sous charge, après les corrections

p50 / p95 / p99 en millisecondes (en s quand c'est indiqué) ; aucune requête n'a échoué, à aucun niveau,
après les corrections. La réclamation des agents est un long polling de 5 s : sa latence est l'attente
quand aucun scan n'est en file, et ce qui dépasse 5 s est de l'attente de file.

| Route | 1 utilisateur | 10 | 50 | 100 |
|---|---|---|---|---|
| `login` | 58 / 83 / 109 | 52 / 107 / 180 | 1722 / 8239 / 9285 | 4706 / 20.2 s / 21.6 s |
| `issues_admin` | 154 / 184 / 191 | 168 / 450 / 536 | 2355 / 3771 / 5096 | 4509 / 6456 / 7049 |
| `issues_admin_filtered` | 167 / 185 / 186 | 161 / 312 / 355 | 1996 / 3070 / 4836 | 4482 / 6711 / 7235 |
| `issues_admin_search` | 187 / 202 / 203 | 228 / 322 / 322 | 2130 / 3494 / 3848 | 5895 / 7922 / 8551 |
| `issues_admin_deep_page` | 154 / 207 / 212 | 164 / 208 / 227 | 1556 / 2978 / 3186 | 4922 / 6591 / 7285 |
| `issues_reader` | — | 192 / 563 / 611 | 1919 / 3495 / 4584 | 4466 / 7910 / 8688 |
| `issues_reader_filtered` | — | 159 / 327 / 474 | 1621 / 3061 / 3169 | 4308 / 6337 / 8101 |
| `issue_detail` | 31 / 53 / 54 | 28 / 62 / 84 | 766 / 2194 / 2723 | 1531 / 5131 / 5510 |
| `issue_triage` | — | 26 / 47 / 60 | 907 / 2452 / 4321 | 2357 / 10.3 s / 10.8 s |
| `dashboard` | 535 / 544 / 545 | 1156 / 2056 / 2490 | 6414 / 11.6 s / 11.9 s | 17.4 s / 23.6 s / 24.5 s |
| `dashboard_trends` | 100 / 103 / 104 | 106 / 168 / 178 | 676 / 2934 / 4133 | 3681 / 6621 / 7713 |
| `posture_analytics` | 271 / 272 / 273 | 229 / 335 / 350 | 1617 / 3650 / 4847 | 3950 / 9992 / 11.0 s |
| `security_overview` | 133 / 181 / 185 | 163 / 249 / 254 | 848 / 2024 / 3225 | 2791 / 4159 / 4702 |
| `scorecards_global` | 359 / 372 / 373 | 161 / 302 / 333 | 1327 / 3537 / 5239 | 3796 / 8919 / 10.1 s |
| `scorecard_repository` | 85 / 99 / 100 | 62 / 120 / 122 | 609 / 1370 / 1457 | 2805 / 6204 / 6754 |
| `repositories` | — | 35 / 70 / 76 | 1233 / 4493 / 6105 | 3225 / 10.3 s / 13.9 s |
| `containers` | 35 / 35 / 36 | 30 / 66 / 72 | 1243 / 2269 / 2739 | — |
| `scans` | 184 / 190 / 191 | 127 / 176 / 176 | 791 / 1480 / 1774 | — |
| `inventory_search` | 559 / 616 / 621 | 656 / 1033 / 1062 | 2705 / 3939 / 4137 | 2730 / 3646 / 3687 |
| `licenses_summary` | 128 / 129 / 129 | 48 / 110 / 114 | 2065 / 4878 / 5126 | 334 / 2068 / 2410 |
| `licenses_inventory` | 699 / 775 / 781 | 750 / 891 / 893 | 5005 / 7508 / 7836 | 6021 / 6674 / 6789 |
| `owasp_coverage` | 357 / 392 / 395 | 597 / 961 / 1010 | 3361 / 4267 / 4726 | 1940 / 2842 / 3020 |
| `remediation_debt` | 210 / 210 / 210 | 249 / 340 / 380 | 1375 / 2132 / 2680 | — |
| `export_csv` | 24 / 34 / 35 | 16 / 24 / 26 | 477 / 1369 / 1679 | — |
| `gate` | 65 / 86 / 95 | 52 / 98 / 120 | 1986 / 6054 / 7433 | 5199 / 15.2 s / 15.8 s |
| `scan_trigger` | 29 / 49 / 54 | 20 / 46 / 91 | 1643 / 3988 / 4981 | 4077 / 9880 / 10.6 s |
| `agent_claim` | 5072 / 5106 / 5141 | 5066 / 5149 / 5314 | 6301 / 8609 / 10.5 s | 9464 / 17.7 s / 18.0 s |
| `agent_result` | 795 / 1578 / 1865 | 709 / 1763 / 1829 | 3641 / 6953 / 8770 | 5857 / 11.7 s / 12.2 s |
| *débit* | 4,3 req/s | 10,9 req/s | 17,5 req/s | 16,8 req/s |

Un tiret est une route que les utilisateurs du niveau n'ont pas atteinte en 90 s : avec un seul
utilisateur, les écrans d'un lecteur ; à cent, les derniers écrans de la boucle des administrateurs. Le
débit cesse de croître entre 50 et 100 : le serveur est saturé.

### Ce que le serveur a fait

| | 1 utilisateur | 10 | 50 | 100 |
|---|---|---|---|---|
| CPU de MySQL, moyen / max (sur 400 %) | 15 % / 38 % | 126 % / 332 % | 327 % / 391 % | 307 % / 394 % |
| Pool : actives, moyenne / max (sur 10) | 0,6 / 3 | 2,3 / 7 | 7,8 / 10 | 6,9 / 10 |
| Pool : requêtes en attente, moyenne / max | 0 / 0 | 0 / 0 | 21 / 46 | 47 / 107 |
| Pool : attente moyenne d'une connexion | 0,07 ms | 0,2 ms | 181 ms | 469 ms |
| Pool : expirations | 0 | 0 | 0 | 0 |
| CPU de la JVM, moyen (sur 10 cœurs) | 3 % | 5 % | 9 % | 16 % |
| Tas utilisé, max (sur 1 536 Mio) | 1 234 Mio | 1 200 Mio | 1 140 Mio | 1 486 Mio |
| Pauses du GC : nombre, total | 20, 0,2 s | 57, 0,7 s | 124, 1,7 s | 199, 4,4 s, **22 complètes** |

**La limite est le CPU de la base, pas le pool.** Dès cinquante utilisateurs, MySQL tient ses quatre cœurs
à plus de 80 %, et le CPU du plan de contrôle reste sous un cinquième de cœur : un pool plus grand
donnerait à la base davantage de requêtes à exécuter à la fois sur les mêmes cœurs. À cinquante
utilisateurs, la latence de chaque route est surtout son attente d'une connexion (181 ms en moyenne,
plusieurs secondes en queue de distribution) derrière les requêtes listées plus bas. À cent, le tas de
1,5 Gio s'est rempli — chaque tableau de bord en cours tient le stock qu'il a lu — et G1 a enchaîné 22
collections complètes dans les six dernières secondes du niveau, l'ensemble vivant atteignant 1,4 Gio.

### Avant les corrections, pour comparer

p95, avant → après (un taux d'erreur est la part des requêtes échouées, toutes par expiration) :

| Route | 1 utilisateur | 10 | 50 | 100 |
|---|---|---|---|---|
| `login` | 46.5 s → 83 | 60.0 s (24 %) → 107 | 60.0 s (35 %) → 8239 | 60.0 s (33 %) → 20.2 s |
| `gate` | 44.0 s → 86 | 57.7 s (3 %) → 98 | 60.0 s (56 %) → 6054 | 60.0 s (45 %) → 15.2 s |
| `dashboard` | 25.4 s → 544 | 87.2 s → 2056 | 103 s → 11.6 s | — → 23.6 s |
| `security_overview` | 18.5 s → 181 | 35.6 s → 249 | — → 2024 | — → 4159 |
| `issue_triage` | — → — | 8357 → 47 | 55.2 s (6 %) → 2452 | 60.0 s (48 %) → 10.3 s |
| `issue_detail` | 71 → 53 | 1856 → 62 | 22.7 s → 2194 | 33.4 s → 5131 |
| `repositories` | — → — | 50.1 s → 70 | — → 4493 | — → 10.3 s |
| `agent_claim` | 30.0 s (12 %) → 5106 | 30.0 s (33 %) → 5149 | 30.0 s (75 %) → 8609 | 30.0 s (40 %) → 17.7 s |
| `agent_result` | 49.0 s → 1578 | 59.4 s → 1763 | 21.1 s → 6953 | — → 11.7 s |

Avant, l'attente moyenne d'une connexion était de 1,9 s avec un seul utilisateur. La liste des constats
paraît plus rapide à cinquante utilisateurs avant qu'après (2,6 s contre 3,8 s au p95) seulement parce
qu'avant, les utilisateurs restaient bloqués sur d'autres écrans et l'ouvraient quatre fois moins souvent.

## Ce qui cassait, et ce qui a été corrigé

### La barrière lisait tout l'inventaire à chaque verdict (V96)

Un verdict porte les écosystèmes de sa cible qu'aucune règle installée ne couvre, et pour répondre d'une
cible la barrière interrogeait le parc : `select distinct repo_id, container_id, purl from t_component` —
391 844 lignes et 1,65 s de MySQL par appel. Le tableau de bord et la vue d'ensemble de sécurité posaient
la même question de chaque cible à chaque appel ; la grille OWASP et la couverture des jeux de règles la
posaient sans cibles (30 000 lignes). Le commentaire de la requête affirmait que la distinction gardait la
réponse proportionnelle aux écosystèmes ; un purl porte un nom et une version, ce n'était donc pas le cas.

La couverture des règles ne lit d'un purl que son type, le préfixe jusqu'à la première barre oblique. V96
le stocke dans `t_component.purl_type`, une colonne générée que le moteur tient à jour à chaque écriture,
indexée avec la cible du composant ; la barrière lit celui de sa cible sur le préfixe de l'index, la
réponse du parc est un parcours d'index par sauts (1 500 entrées au lieu d'un million, 350 → 40 ms).
Barrière 1,85 s → 45 ms ; tableau de bord 2,9 s → 0,5 s ; vue d'ensemble de sécurité 2,0 s → 0,17 s.

### Dix requêtes relisaient chaque SBOM pour savoir si un scan en avait un (V98)

`sbom is null` et `sbom is not null` figuraient dans dix requêtes des scans : le recensement des décomptes
de licences, les scans de l'inventaire, le dernier scan terminé de chaque cible. MySQL range un long
`longtext` hors de la ligne et le relit pour le tester à nul — chaque SBOM stocké, 500 ms par requête
contre 0,3 ms pour un comptage par statut sur les mêmes lignes. Le résumé des licences, l'inventaire des
licences, les scorecards et l'analyse de posture en exécutaient deux chacun. V98 ajoute `t_scan.has_sbom`,
une colonne générée que les requêtes lisent à la place. Résumé des licences 1,2 s → 20 ms, scorecards
1,35 s → 0,2 s, analyse de posture 1,4 s → 0,27 s. Le coût supprimé croissait avec les SBOM conservés ; de
vrais SBOM sont plus gros que les 340 Ko de ce parc.

### L'historique des scans triait la table avec ses SBOM (V97)

La liste des scans et les scans récents du tableau de bord lisaient `t_scan` du plus récent au plus ancien
avec une limite, et aucun index ne commençait par cet ordre. MySQL triait toute la table, et son tri
emporte les colonnes sélectionnées — le SBOM parmi elles. V97 ajoute un index sur `(created_at, id)` : la
requête est passée de 493 à 5 ms, la route de 630 à 110 ms.

Chaque correction a un test qui échoue sans elle (vérifié par mutation) ; les migrations ont tourné sur le
parc semé en 10 s ensemble, les deux colonnes générées reconstruisant leur table.

## Ce qui a été trouvé et pas corrigé

Chacun de ces points dépasse une correction ciblée, et c'est par eux qu'il faut continuer pour un parc de
cette taille.

1. **La liste des constats trie le stock ouvert à chaque page.** L'ordre par défaut est un `case` sur la
   sévérité, qu'aucun index ne peut servir : chaque page trie les 60 000 constats ouverts et leurs colonnes
   sélectionnées. 135 ms sans charge ; 150 ms par appel dans MySQL à cinquante utilisateurs, la plus grande
   part du temps de la base (180 s sur 90). Un rang de sévérité stocké, indexé avec l'état et la date de
   dernière observation, ferait d'une page un parcours d'index — au prix d'un rang écrit dans une migration
   en plus de `Severity`, ce qu'`IssueOrdering` existe pour éviter.
2. **Le tableau de bord lit et renvoie toute la posture en échec.** Chaque appel lit tous les constats
   ouverts (60 000 lignes) pour noter chaque cible, compte le stock par sévérité en six requêtes de 35 à
   50 ms chacune, et répond 1,7 Mo : chaque cible en échec avec chacune de ses violations. 0,45 s sans
   charge, 2,1 s au p95 à dix utilisateurs, et la raison la plus probable du tas plein à cent. Un index sur
   `t_issue (state, severity, type, triage_status)` fait passer un comptage par sévérité de 47 à 2,5 ms
   (mesuré) ; la charge utile et la notation à chaque appel demanderaient une réponse paginée ou résumée,
   donc un changement de contrat.
3. **La recherche d'inventaire parcourt chaque ligne de composant.** `name like '%…%'` ne peut pas utiliser
   d'index : 1,8 s de MySQL par appel sous charge, un million de lignes lues. Une recherche par préfixe, ou
   un index n-gramme, est une décision sur ce que la recherche promet.
4. **L'inventaire des licences coûte 0,6 s de CPU du plan de contrôle par appel**, servi depuis la mémoire
   depuis cette version, sur 300 cibles de trois scans et mille composants chacune. Il croît avec
   l'inventaire conservé, pas avec les utilisateurs.
5. **L'historique des scans lit encore le SBOM de chaque scan qu'il liste** : la liste charge des entités,
   et une entité porte son document — 50 × 340 Ko par page, 415 ms par appel dans MySQL à cinquante
   utilisateurs. Une projection sans les charges utiles le supprimerait ; il en va de même partout où une
   entité de scan est chargée pour son statut.
6. **Une connexion coûte une connexion à la base comme n'importe quelle route**, elle a donc attendu avec
   les autres : 8 s au p95 à cinquante utilisateurs. Le hachage du mot de passe n'est pas le coût (58 ms
   sans charge).

## Dimensionnement

Ce que cette campagne appuie, pour un parc d'environ 300 cibles et 60 000 constats ouverts ; la page
[Dimensionnement](../../../docs-site/administration/sizing.fr.md) porte la même chose pour les
exploitants.

- **Le CPU de la base décide combien de personnes peuvent travailler à la fois.** Quatre cœurs ont servi
  dix utilisateurs très actifs (environ cent personnes à rythme humain) avec l'écran le plus lent à 2 s au
  p95, et étaient saturés à cinquante. Donnez à MySQL quatre cœurs pour quelques centaines de cibles et une
  équipe de cent personnes, huit au-delà, et n'augmentez le pool qu'avec les cœurs : les dix connexions de
  Hikari n'ont jamais été la limite ici.
- **Tas** : 1,5 Gio a tenu cinquante utilisateurs ; à cent, il s'est rempli. 2 Gio (la limite du chart)
  pour une équipe, 3 à 4 Gio de tas — une limite de conteneur de 4 à 5 Gio — pour des parcs de cette
  taille avec beaucoup de personnes à la fois.
- **Taille de la base** : 875 Mo pour ce parc. Par scan conservé, son SBOM (340 Ko ici ; un vrai document
  Syft fait souvent 1 à 5 Mo) et environ 0,3 Ko par ligne de composant avec ses index ; par constat
  environ 1 Ko, par observation 0,35 Ko. La purge de rétention borne les SBOM, pas les lignes de
  composants, conservées pour l'inventaire.
- **Ingestion** : quatre agents ont rendu 300 résultats de 420 Ko en 70 s — environ 4 résultats par
  seconde, 0,8 s chacun, quelque 15 000 par heure — sans ralentir les écrans à dix utilisateurs.
- **Le buffer pool** : la composition laisse à MySQL sa valeur par défaut de 128 Mio, et l'ensemble de
  travail de ce parc était plus grand ; les requêtes ci-dessus étaient limitées par le CPU plutôt que par le
  disque sur cette machine, mais sur un serveur au stockage plus lent, donnez à InnoDB un buffer pool proche
  de la taille des données (`--innodb-buffer-pool-size`).

## Un test de fumée nocturne (proposé, non branché)

La campagne complète prend une demi-heure et une machine pour elle seule, ce que la CI ne doit pas payer à
chaque poussée. Une version de fumée pourrait tourner dans `nightly.yml` en cinq minutes environ : semer
30 cibles et deux tours (`seed.py --targets 30 --rounds 2`, environ une minute), un niveau de dix
utilisateurs pendant 60 s, et des seuils k6 qui font échouer le travail — un taux d'erreur nul sur chaque
route, la barrière sous 300 ms et le tableau de bord sous 2 s au p95. Sur un runner, les chiffres ne sont
pas comparables à ceux de ce rapport : les seuils attraperaient un retour des défauts ci-dessus (des
secondes là où des millisecondes sont attendues), pas une dérive de quelques dizaines de pour cent.

## Rejouer

```bash
(cd vectispire-java && ./gradlew :vectispire-core:bootJar -x test)
load/env.sh up
python3 load/seed/seed.py --governor-password "$(cat load/.state/bootstrap_password)"
load/env.sh snapshot && load/env.sh app
load/probe.sh
LEVELS="1 10 50 100" DURATION=90s load/run.sh monlibelle
python3 load/report.py load/results/<campagne>
load/env.sh down
```
