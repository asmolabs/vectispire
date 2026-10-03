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
  classement, l'inventaire de la cible pour sa fiche), jamais un second décompte.
- **Pas de bonus pour un scan terminé.** En avoir un est la condition d'une note ; une cible sans
  scan reste `NO_DATA` (décision 0007), décidé avant tout score, exactement comme aujourd'hui.
- **Maintenu à 1, jamais 0** : zéro se lit « plus rien à perdre », la saturation que ceci remplace.
- **Les points de risque sont affichés** à côté du score — sur la fiche, sur la pastille
  (`F · 312 pts`, par exemple) et dans le classement, qui les utilise pour départager deux cibles de
  même score. Dans F le score reste à 1 tandis que les points de risque continuent de baisser, et une
  équipe loin dans F voit ce qu'elle a corrigé. Ils sont une somme de ce qui est ouvert et présentés
  comme tels, jamais comme un pourcentage.
- **Inchangé** : les seuils, ce qui compte (problèmes ouverts, triage réglé — `not_affected`,
  `fixed` — exclu), le plafond de couverture sur le score d'un projet, d'une solution ou du portefeuille
  (la part observée), `NO_DATA`, et les recommandations. Le score d'une portée applique la formule au
  backlog cumulé de la portée, comme l'actuel ; la route de simulation ne montre que des cibles, et le
  déploiement y ajoute les portées avant la bascule.

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
- **Garder le bonus de +5.** C'est une constante pour chaque cible notée : il ne change que le plafond
  commun à toutes, et cache une haute ou une licence sur une fiche autrement propre.

## Conséquences

**Chaque note bouge, dans un seul sens** : la plupart des cibles se lisent plus bas le jour où la
formule change (le tableau ci-dessus, et la grille). Le changement est visible des intégrations, pas
seulement à l'écran :

| Consommateur | Ce qu'il lit | Ce qu'il voit |
|---|---|---|
| Pastille publique, `GET /api/v1/scorecards/badges/{token}.svg`, intégrée aux README d'autres personnes | la lettre et la couleur de la note | une autre lettre et une autre couleur au rendu suivant, sans que personne ait touché au dépôt |
| `GET /api/v1/scorecards/repositories/{repoId}`, `…/containers/{containerId}`, `…/global` | `score`, `grade` | de nouvelles valeurs ; un nouveau champ `riskPoints` |
| `GET /api/v1/projects/{id}/compliance`, `GET /api/v1/solutions/{id}/compliance` | le `scorecard` intégré | comme ci-dessus, sur le backlog et la couverture de la portée |
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

1. **Avant la bascule**, la route de simulation liste les projets et les solutions à côté des cibles,
   pour que la nouvelle note d'une portée soit vue sur le parc avant de partir.
2. **Une seule version bascule**, partout à la fois : `computeScorecard` calcule la formule de
   `CandidateScore` avec `Weights.PROPOSED`, `SecurityScorecard` gagne `riskPoints`, la pastille les
   affiche, le classement départage par eux. Pas de drapeau ni de période avec deux formules actives :
   deux notes pour une cible sur deux écrans est le défaut que l'unification du classement a fermé.
3. **Les notes de version** la portent sous **« Changements visibles d'une intégration »** : la
   formule, le tableau ci-dessus, « chaque note peut baisser — rien n'a changé dans votre dépôt », le
   nouveau champ `riskPoints`, et le nouveau texte de la pastille.
4. `CandidateScore` cesse d'être une candidate (renommée dans le domaine du scorecard) et la route de
   simulation est retirée à la version suivante, quand plus personne n'a besoin de la comparaison.
