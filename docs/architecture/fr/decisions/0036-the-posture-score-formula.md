# 0036 — La formule du score de posture

**Date :** 2026-10-03 · **Statut :** proposée · **Décideur :** Laurent Boucher

## Contexte

La note du scorecard d'une cible (A+ à F) est un seul nombre affiché à cinq endroits : les fiches des
dépôts et des images, les fiches de portée des projets et des solutions, le classement de maturité du
tableau de bord, et la pastille SVG publique qu'une équipe colle dans son README. Depuis que le
classement a cessé de noter avec ses propres poids, les cinq lisent un seul calcul
(`SecurityScorecardService.computeScorecard`) :

```
score = borné(0, 100, 100 − 25·KEV − 8·critique − 4·haut − 5·licence interdite + 5·[un scan terminé])
```

KEV est compté en plus de la sévérité ; les moyennes et les basses ne pèsent rien. Les seuils sont
ceux de `SecurityGrade.fromScore` : 95 A+, 85 A, 70 B, 55 C, 40 D, en dessous F.

**L'échelle sature là où se trouvent les parcs qu'il faut le plus distinguer.** Vingt-sept hautes, ou
quatre critiques exploitées, donnent déjà 0, F — tout comme deux cents hautes, si bien qu'une équipe
qui en corrige cent soixante-dix ne voit rien bouger. À l'autre bout, cinquante et cinq cents
moyennes ouvertes donnent toutes deux 100, A+, parce qu'une moyenne ne pèse rien. Et le +5 d'un scan
terminé relève chaque cible notée des mêmes cinq points — une cible n'est notée qu'une fois qu'elle a
un scan terminé (décision [0007](0007-none-is-not-an-empty-list.md), `NO_DATA` sinon) — si bien que le
seul effet du bonus est que le cent d'une cible propre absorbe une haute, ou une licence interdite,
sans bouger.

Une candidate (`CandidateScore`, reliée à aucune note) et une route de simulation réservée aux
administrateurs (`GET /api/v1/scorecards/simulation`) ont été ajoutées le 2026-10-03 pour que le
remplacement se décide sur des chiffres. Le responsable produit a validé une calibration le même jour.
Sur les parcs semés de `ScoreSimulationRoutesTest` — les plaintes de l'élément de backlog, plus des
parcs à licences — les deux formules donnent (points de risque : voir la décision) :

| Cible (ouverts, non réglés) | Actuelle | Candidate | Points de risque |
|---|---|---|---|
| propre | 100 A+ | 100 A+ | 0 |
| 1 critique | 97 A+ | 83 B | 10 |
| 1 critique exploitée | 72 B | 54 D (plafonné, 63 sinon) | 25 |
| 50 moyennes | 100 A+ | 63 C | 25 |
| 500 moyennes | 100 A+ | 1 F | 250 |
| 27 hautes | 0 F | 14 F | 108 |
| 4 critiques exploitées | 0 F | 16 F | 100 |
| 2 critiques, 6 hautes, 40 moyennes, 120 basses | 65 C | 24 F | 79 |
| 1 licence interdite | 100 A+ | 93 A | 4 |
| 1 critique, 1 licence interdite | 92 A | 78 B | 14 |
| 10 licences interdites | 55 C | 48 D | 40 |
| jamais scannée, 1 haute | pas de données | pas de données | — |

| Note | Actuelle | Candidate |
|---|---|---|
| A+ | 5 | 1 |
| A | 1 | 1 |
| B | 1 | 2 |
| C | 2 | 1 |
| D | 0 | 2 |
| F | 2 | 4 |
| pas de données | 1 | 1 |

Huit des onze cibles notées changent de note, et chaque changement est à la baisse. Ce n'est pas un
hasard de l'échantillon : sur une grille de 144 000 backlogs (0–4 exploitées, 0–7 critiques, 0–29
hautes, des moyennes, des basses, 0–14 licences) aucune note ne monte ; un *score* ne monte qu'à
l'intérieur de F, là où l'actuel a déjà atteint zéro.

**Projets et solutions.** Depuis la première étape du déploiement, la simulation liste chaque projet
et chaque solution que l'appelant voit à côté des cibles : le score actuel que donne la fiche de la
portée face à la candidate sur le backlog cumulé de la portée, le plafond de couverture appliqué aux
deux. Sur les portées que sème `ScoreSimulationRoutesTest` :

| Portée | Cibles (observées) | Ouverts | Licences, candidate (fiche) | Actuelle | Candidate | Points de risque |
|---|---|---|---|---|---|---|
| projet d'un dépôt propre | 1 (1) | — | 0 (0) | 100 A+ | 100 A+ | 0 |
| projet d'un dépôt et d'une image partageant un scan | 2 (2) | 1 haute | 3 (6) | 71 B | 75 B | 16 |
| projet d'un dépôt chargé en critiques et d'un dépôt chargé en moyennes | 2 (2) | 3 critiques, 1 haute, 60 moyennes, 20 basses | 0 (0) | 77 B | 30 F | 66,5 |
| projet dont un dépôt sur deux est scanné, tous deux propres | 2 (1) | — | 0 (0) | 50 D | 50 D | 0 |
| projet vide | 0 | — | — | pas de données | pas de données | — |
| solution du projet propre et du projet critiques/moyennes | 3 (3) | comme ce dernier | 0 (0) | 77 B | 30 F | 66,5 |

Une portée cumule les backlogs de ses cibles, et peut donc se lire plus bas que chacune d'elles — le
dépôt chargé en critiques seul fait 54 D, celui chargé en moyennes 55 C, le projet qui tient les deux
30 F. C'est la formule qui fait son travail : les deux backlogs ensemble sont une exposition plus
grande que chacun.

**La fiche de portée compte certaines licences deux fois.** Elle additionne les inventaires de ses
cibles, et l'inventaire d'une image contient les composants et les constats de licence de chaque scan
qui nomme cette image *et* un dépôt — rattachés au dépôt, dont l'inventaire les contient aussi. Un
projet qui range les deux cibles d'un tel scan facture ces entrées deux fois : trois licences
interdites se lisent six sur la fiche ci-dessus, 71 là où 86 est dû. La fiche propre de chaque cible
les compte une fois, sur le dépôt. La candidate compte les licences d'une portée comme les fiches de
ses cibles — la somme de leurs décomptes, chaque entrée sur la seule cible à laquelle son scan est
attribué — et ses problèmes une fois chacun, quel que soit le nombre de cibles de la portée qu'ils
nomment ; la simulation signale chaque portée dont la fiche diverge (`currentDoubleCounted`). Avec les
six de la fiche, la candidate lirait 60 C au lieu de 75 B.

**Comment une portée agrège ses cibles** (amendement du 2026-10-03). Cumuler les backlogs pénalise la
taille : les deux dépôts ci-dessus à 54 D et 55 C font un projet à 30 F, et un projet de nombreuses
cibles raisonnables se lit plus mal que chacune d'elles. La simulation met donc une seconde agrégation
à côté de la somme dans chaque ligne de portée — le **maillon le plus faible** (`weakestScore`,
`weakestGrade`, `weakestTarget`) : le score de la portée est le score candidat de sa cible observée la
moins bien notée, tel que la ligne de cette cible le donne, et la ligne nomme cette cible (nature, id,
nom — une des cibles visibles que liste la même réponse, choisie parmi les seules cibles visibles de la
portée). Le plafond de couverture s'applique à la portée comme à la somme : le score de la cible
observée la plus faible est plafonné à la part observée. Une portée sans cible observée est `NO_DATA`,
et une cible jamais analysée n'entre jamais en lice, même quand un import y a laissé des problèmes
ouverts — ceux-là entrent toujours dans le backlog de la somme et dans les points de risque. Les points
de risque restent ceux de la somme dans les deux agrégations : chaque problème et chaque licence une
fois, ce qui est ouvert dans la portée, pas la façon de la noter. Sur les portées du tableau ci-dessus :

| Portée | Cibles (observées) | Actuelle | Somme | Maillon le plus faible | Points de risque | Cible la plus faible |
|---|---|---|---|---|---|---|
| projet d'un dépôt propre | 1 (1) | 100 A+ | 100 A+ | 100 A+ | 0 | le dépôt propre |
| projet d'un dépôt et d'une image partageant un scan | 2 (2) | 71 B | 75 B | 75 B | 16 | le dépôt (1 haute, 3 licences) |
| projet d'un dépôt chargé en critiques et d'un dépôt chargé en moyennes | 2 (2) | 77 B | 30 F | 54 D | 66,5 | le dépôt chargé en critiques |
| projet dont un dépôt sur deux est scanné, tous deux propres | 2 (1) | 50 D | 50 D | 50 D (plafonné depuis 100) | 0 | le dépôt scanné |
| projet dont le seul dépôt n'a jamais été scanné, 1 haute ouverte | 1 (0) | pas de données | pas de données | pas de données | — | — |
| projet vide | 0 | pas de données | pas de données | pas de données | — | — |
| solution du projet propre et du projet critiques/moyennes | 3 (3) | 77 B | 30 F | 54 D | 66,5 | le dépôt chargé en critiques |

Et sur deux projets semés pour montrer ce que l'agrégation décide, chaque cible un dépôt scanné :

| Portée | Cibles (observées) | Actuelle | Somme | Maillon le plus faible | Points de risque | Cible la plus faible |
|---|---|---|---|---|---|---|
| 20 dépôts, 4 moyennes chacun (chacun 96 A+) | 20 (20) | 100 A+ | 48 D | 96 A+ | 40 | le premier d'entre eux |
| 10 dépôts propres + 1 portant une critique exploitée | 11 (11) | 72 B | 54 D | 54 D | 25 | le dépôt exploité |
| solution des deux | 31 (31) | 72 B | 31 F | 54 D | 65 | le dépôt exploité |

Sous la somme, le projet des vingt dépôts à moyennes se lit D parce qu'il en compte vingt, alors que
chacune de ses cibles se lit A+ et qu'un projet d'une seule d'entre elles le ferait aussi ; sous le
maillon le plus faible, il se lit A+. Aucune des deux ne cache la critique exploitée derrière les dix
dépôts propres : les deux lisent 54 D, le plafond de l'exploité.

## Décision

**Le score du scorecard devient celui de la candidate, avec la calibration validée**, partout où
l'actuel est lu — toujours un seul calcul, sur chaque écran et sur la pastille.

```
points de risque = 25·exploité + 10·critique + 4·haut + 0,5·moyen + 0,125·bas + 4·licence interdite
score            = max(1, arrondi(100 × exp(−points de risque / 55)))   plafonné à 54 si un problème est exploité
```

- **Chaque problème retire une part de ce qui reste**, pas un nombre fixe de points : le score baisse
  vite pour les premiers problèmes et continue de baisser sans atteindre le plancher, donc un backlog
  deux fois plus grand a toujours un score plus bas. `k = 55` est le backlog pondéré qui amène le
  score à 100/e ≈ 37.
- **La calibration** (validée le 2026-10-03) : un critique donne B (83), un critique exploité D (le
  plafond), cinquante moyennes C (63), une licence interdite A (93). Avec un moyen à 1, aucun `k` ne
  tient à la fois la première et la troisième — B demande `k < 61,5`, C demande `k ≥ 83,6` — d'où un
  moyen à 0,5, et un bas au quart de celui-ci.
- **Exploité est une classe à part, quelle que soit la sévérité**, et un problème qui y est n'est
  compté sous aucune sévérité. **Tout problème exploité plafonne la note à D** (score 54, le haut de
  D), ce que dit la description même de D : « vulnérabilités critiques non résolues ou menaces KEV ».
- **Une licence interdite pèse 4, le poids d'un haut**, comptée exactement comme la fiche la compte
  aujourd'hui — le décompte de l'inventaire (`LicenseGovernanceService.violationsByTarget` pour le
  classement, l'inventaire de la cible pour sa fiche), jamais un second décompte. Celui d'une portée
  est la somme des décomptes de ses cibles, chaque entrée comptée une fois (le double compte
  ci-dessus est corrigé par la bascule).
- **Pas de bonus pour un scan terminé.** En avoir un est la condition d'une note ; une cible sans
  scan reste `NO_DATA` (décision 0007), décidé avant tout score, exactement comme aujourd'hui.
- **Maintenu à 1, jamais 0** : zéro se lit « plus rien à perdre », la saturation que ceci remplace.
- **Les points de risque ne sont affichés qu'aux lecteurs connectés** — à côté du score sur la fiche
  de la cible, sur le scorecard d'un projet et d'une solution, et dans le classement, qui les utilise
  pour départager deux cibles de même score. Dans F le score reste à 1 tandis que les points de risque
  continuent de baisser, et une équipe loin dans F voit ce qu'elle a corrigé. Ils sont une somme de ce
  qui est ouvert et présentés comme tels, jamais comme un pourcentage.
- **La pastille publique montre la lettre, jamais les points de risque** (amendement du 2026-10-03).
  La pastille est anonyme et intégrée aux README d'autres personnes : une lettre dit comment une cible
  est notée, les points diraient combien est ouvert sur elle et, de rendu en rendu, comment cela
  bouge — un attaquant apprendrait quand un backlog grossit après une version, quand un correctif
  arrive, et où regarder en premier. La lettre est grossière à dessein ; les points restent derrière
  une session, comme tout autre chiffre du backlog.
- **Inchangé** : les seuils, ce qui compte (problèmes ouverts, triage réglé — `not_affected`,
  `fixed` — exclu), le plafond de couverture sur le score d'un projet, d'une solution ou du portefeuille
  (la part observée), `NO_DATA`, et les recommandations.
- **Une portée est notée par son maillon le plus faible — recommandé par le responsable produit, en
  attente d'acceptation** (amendement du 2026-10-03). Le score d'un projet ou d'une solution est le
  plus bas score de ses cibles observées, chacun calculé comme le calcule la fiche de la cible,
  plafonné à la part observée de la portée ; `NO_DATA` quand aucune n'est observée ; la fiche nomme la
  cible dont vient la note. Une portée n'est pas plus sûre que sa cible la plus exposée, et sa note ne
  doit pas dépendre de sa taille : vingt cibles de quatre moyennes chacune sont vingt cibles A+, pas un
  projet D. Ses points de risque restent la somme du backlog ouvert de la portée, chaque problème et
  chaque licence une fois, pour qu'une grande portée montre toujours ce qui est ouvert. L'autre option
  sur la table est la **somme** — la formule sur le backlog cumulé de la portée, comme le calcule la
  fiche de portée actuelle — qui lit dans deux backlogs ensemble une exposition plus grande que dans
  chacun, et note une portée d'autant plus bas qu'elle tient de cibles (les tableaux ci-dessus). Le
  score du portefeuille est hors de cette question — la simulation ne le compare pas — et reste le
  calcul cumulé.

## Alternatives rejetées

- **La formule linéaire avec des plafonds plus grands** (ou des charges plus petites par problème).
  Elle déplace la saturation au lieu de la supprimer : tout `100 − Σ` atteint zéro à un certain
  backlog, et au-delà toutes les cibles se lisent de nouveau pareil. Charger les moyennes assez
  linéairement pour distinguer cinquante de cinq cents envoie cinquante moyennes en F à elles seules.
- **Normaliser chaque composante** (un sous-score par sévérité, par licence, moyenné ou pondéré). Elle
  répond à « à quel point chaque classe va mal » plutôt qu'à « à quel point cette cible est exposée »,
  laisse une classe propre relever une cible qui échoue sur une autre, et demande une référence par
  classe (un nombre « normal » de hautes) qu'aucun parc ne fournit. Chaque nombre de la fiche
  dépendrait alors d'une constante que personne ne peut expliquer sur la pastille.
- **`k = 85`, moyen à 1.** Cinquante moyennes y donnent C, mais un critique donne alors A (89) — une
  vulnérabilité critique sur une fiche notée A est précisément ce que la note doit éviter. Le B du
  critique demande `k < 61,5` ; aucun `k` unique ne sert les deux avec un moyen à 1.
- **Une portée notée par la moyenne des scores de ses cibles**, simple ou pondérée par une mesure
  de taille quelconque. Elle supprime la pénalité de taille, mais une cible critique se cache derrière
  des cibles propres : dix dépôts propres et un dépôt portant une critique exploitée font en moyenne 96,
  A+, pour un projet que la somme et le maillon le plus faible notent tous deux D pour sa critique
  exploitée. La note dirait le contraire de ce que tient le projet.
- **Garder le bonus de +5.** C'est une constante pour chaque cible notée : il ne change que le plafond
  commun à toutes, et cache une haute ou une licence sur une fiche autrement propre.

## Conséquences

**Chaque note bouge, dans un seul sens** : la plupart des cibles se lisent plus bas le jour où la
formule change (le tableau ci-dessus, et la grille). Le changement est visible des intégrations, pas
seulement à l'écran :

| Consommateur | Ce qu'il lit | Ce qu'il voit |
|---|---|---|
| Pastille publique, `GET /api/v1/scorecards/badges/{token}.svg`, intégrée aux README d'autres personnes | la lettre et la couleur de la note | une autre lettre et une autre couleur au rendu suivant, sans que personne ait touché au dépôt — et toujours aucun chiffre : les points de risque n'y figurent pas |
| `GET /api/v1/scorecards/repositories/{repoId}`, `…/containers/{containerId}`, `…/global` | `score`, `grade` | de nouvelles valeurs ; un nouveau champ `riskPoints` |
| `GET /api/v1/projects/{id}/compliance`, `GET /api/v1/solutions/{id}/compliance` | le `scorecard` intégré | comme ci-dessus, sur le backlog et la couverture de la portée ; `licenseViolationCount` baisse là où un scan nommait une image et un dépôt de la portée |
| `GET /api/v1/dashboard/posture-analytics` | `securityScore`, `maturityGrade` du classement de maturité, et son ordre | de nouvelles valeurs, un nouvel ordre entre ex æquo départagés par les points de risque |
| L'interface : le composant scorecard, le classement du tableau de bord, les pages projet et solution | les champs ci-dessus | les nouveaux chiffres et les points de risque |

**Rien d'autre ne lit la note.** La barrière décide sur les sévérités, KEV et sa politique, jamais sur
la note ni le score ; aucun événement SIEM, notification, ticket, export (SARIF, VEX, CSAF,
CycloneDX) ni les modèles CI livrés (`ci/gitlab/vectispire-gate.gitlab-ci.yml`) ne la portent. Un
consommateur extérieur au produit qui applique un seuil à la lettre de la pastille ou au `score` de
l'API — un tableau de bord de tableaux de bord, un contrôle « pas pire que B » dans le pipeline de
quelqu'un — la verra baisser, et rien dans Vectispire ne peut trouver un tel consommateur pour nous.

**Des tests figent les poids actuels** (`SecurityScorecardDatabaseTest`, `ScorecardRoutesTest`,
`BadgeRoutesTest`, `TrendsRoutesTest`, `ProjectAggregatesRoutesTest`, les fixtures de l'interface) et
bougent avec la bascule ; la section « Comment la note du scorecard est calculée » du guide (en + fr)
est réécrite avec elle.

**Les constantes deviennent un contrat.** Comme les ingrédients d'une empreinte, un poids ou un `k`
changé plus tard déplace chaque pastille du jour au lendemain ; tout changement ultérieur est une
décision enregistrée ici, pas un réglage. C'est aussi pourquoi les poids ne sont pas configurables
par installation : deux installations tenant le même parc le notent pareil, ce pour quoi les
fenêtres SLA ont été tenues hors du score.

## Déploiement

Décidé avec le responsable produit le 2026-10-03 (amendement) :

1. **Avant la bascule**, la route de simulation liste les projets et les solutions à côté des cibles,
   pour que la nouvelle note d'une portée soit vue sur le parc avant de partir — fait le 2026-10-03,
   le tableau des portées ci-dessus ; le responsable produit accepte cette décision sur ce tableau.
   Chaque ligne de portée porte les deux agrégations, la somme et le maillon le plus faible, depuis le
   2026-10-03 (amendement), pour que le choix entre elles se fasse sur les mêmes chiffres.
2. **Une seule version bascule, la 0.11.0**, partout à la fois : `computeScorecard` calcule la formule
   de `CandidateScore` avec `Weights.PROPOSED`, `SecurityScorecard` gagne `riskPoints`, le classement
   départage par eux, la pastille garde sa seule lettre. Pas de drapeau ni de période avec deux
   formules actives : deux notes pour une cible sur deux écrans est le défaut que l'unification du
   classement a fermé.
3. **Le double compte des portées est corrigé par la même bascule** : le terme de licence d'une portée
   devient la somme des décomptes de ses cibles, comme la candidate le calcule déjà, et aucune entrée
   n'est facturée deux fois. Pas avant — une fiche de portée qui bougerait seule une version avant la
   formule serait un second changement inexpliqué.
4. **Les notes de version** la portent sous **« Changements visibles d'une intégration »** : la
   formule, les tableaux ci-dessus, le nouveau champ `riskPoints` (routes authentifiées seulement), et
   la phrase qu'un lecteur doit lire d'abord — *les notes baissent parce que les moyennes, les basses
   et chaque problème de plus comptent désormais, pas parce qu'un projet s'est dégradé ; rien n'a
   changé dans votre dépôt*. La façon dont une portée est notée — la note de sa cible la plus faible,
   ou, si la somme est retenue, une note qui peut se lire plus bas que chacune de ses cibles — et le
   nombre de licences d'une portée qui baisse y sont dits aussi.
5. **Le graphique de tendance du tableau de bord marque la bascule** d'une ligne verticale datée
   (« formule du scorecard modifiée », 0.11.0), pour qu'un lecteur qui compare une période de part et
   d'autre voie pourquoi les notes ont bougé. Les séries qu'il trace aujourd'hui sont celles du
   backlog, que la bascule ne déplace pas ; la ligne sert au lecteur qui met une note en regard.
   Décidé avec le responsable produit le 2026-10-03 : la ligne va sur ce graphique et sur **toute
   série du score ajoutée plus tard**, dès sa première version. Aucun graphique du score dans le temps
   n'existe aujourd'hui — le classement et les fiches montrent le score tel qu'il est — donc rien d'autre
   ne la porte encore.
6. `CandidateScore` cesse d'être une candidate (renommée dans le domaine du scorecard) et la route de
   simulation est retirée à la version suivante, quand plus personne n'a besoin de la comparaison.
