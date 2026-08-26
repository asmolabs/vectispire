# Audit approfondi — le pipeline qui n'a jamais tourné

**Date :** 2026-08-25 · **Périmètre :** les quatre axes du prompt · **Méthode :** affirmations
vérifiées en exécutant

> **Une recommandation des trois rapports précédents est retirée ici.** Chacun se terminait par
> « surveiller la première exécution nocturne ». Il n'y en aura pas. L'unique remote du dépôt est
> `git@gitlab.com:asmolabs_be/vectispire.git` et tous les workflows vivent dans
> `.github/workflows/` ; il n'existe aucun `.gitlab-ci.yml`. GitLab n'exécute pas GitHub Actions.
> Confirmé avec le mainteneur au cours de cette passe.

> **État de remédiation.** Les deux recommandations 🔴 ci-dessous sont closes. `.gitlab-ci.yml`
> existe désormais et porte les treize jobs que décrivaient les workflows GitHub ; la vue
> développement et la commande de vérification de signature sont corrigées. Trois choses ont
> changé de forme au passage et sont consignées dans les commentaires du pipeline : le contrôle de
> dérive C4 est plus faible que celui qu'il remplace, un `.gitleaks.toml` de dépôt a été
> nécessaire pour six fixtures délibérées, et l'identité cosign suit le forgeron.

## Notes

| Domaine | Note | Évolution | Ce qui a tranché |
|---|:--:|:--:|---|
| Documentation & Architecture | **8,4** / 10 | ↘ depuis 9,2 | Seize ADR plaident toujours leur cause et la parité tient — mais la vue développement décrit un pipeline CI qui ne tourne pas, et le guide de démarrage dit à l'utilisateur de vérifier une signature contre une identité de workflow qui n'a jamais rien signé |
| Sécurité & Cryptographie | **8,6** / 10 | ↗ depuis 8,0 | Les vingt routes sont fermées et réellement vérifiées désormais ; le dernier garde non vérifié a été trouvé par un balayage des noms de routes, pas par une relecture |
| Qualité du Code & Architecture | **8,2** / 10 | ↘ depuis 8,4 | 1250 tests, quatre lecteurs non bornés restants, et l'empreinte enfin unique. En face : **rien n'exécute tout cela sinon une personne qui le décide**, et trois assertions cette semaine ne pouvaient pas échouer |
| Conformité Réglementaire | **8,8** / 10 | = | Inchangée et solide |
| **Global** | **8,5** / 10 | ↘ depuis 8,6 | |

---

## 1. Le constat : la CI n'existe pas là où le code vit

**Ce qui est vérifiable depuis l'intérieur du dépôt :**

* l'unique remote configuré est GitLab ;
* les trois workflows — `ci.yml`, `nightly.yml`, `release.yml` — sont des GitHub Actions ;
* il n'existe aucun `.gitlab-ci.yml`, et aucun n'a jamais été commité ;
* la documentation référence `https://github.com/Asmo1973/Vectispire` : le projet a donc un passé
  GitHub qu'il semble avoir quitté.

**Ce que cela coûte, concrètement.** Chaque garantie que les sept audits précédents ont créditée à
la CI n'est aujourd'hui appliquée par personne :

| Cru appliqué | En réalité |
|---|---|
| 544 liens de documentation vérifiés à chaque poussée | Seulement quand quelqu'un lance `scripts/check-doc-links.py` |
| Les diagrammes C4 ne peuvent pas diverger de `workspace.dsl` | Seulement quand quelqu'un les régénère |
| 1250 tests unitaires + ArchUnit gardent une fusion | Seulement quand quelqu'un lance `./gradlew check` |
| Les deux images de conteneur se construisent | Jamais construites par une machine |
| Campagne trois moteurs, nocturne | Jamais exécutée par une machine |
| Onze cas navigateur, nocturne | Jamais exécutés par une machine |

Cela explique une observation que trois rapports ont faite sans l'expliquer : `nightly.yml` « n'a
jamais tourné sur un runner ». Il n'a pas tourné, et sur l'hébergement actuel il ne tournera jamais.

**Deux documents l'affirment comme un fait**, ce qui est pire que l'absence :

* La [vue 05 — Développement](../../architecture/bflorat/fr/05_vue_developpement.md) ouvre sa
  section 3 par *« Le pipeline CI exécute automatiquement les étapes de vérification suivantes »*
  et en diagramme quatre.
* [`GETTING_STARTED.fr.md`](../../fr/GETTING_STARTED.fr.md) demande à l'utilisateur de vérifier une
  release avec `cosign verify-blob --certificate-identity "https://github.com/Asmo1973/Vectispire/.github/workflows/release.yml@refs/tags/v1.0.0"`.
  Cette commande épingle une identité qui n'a rien signé. **Une instruction de vérification qui ne
  peut pas réussir est pire que pas d'instruction** : elle apprend à l'utilisateur que le contrôle
  est passé le jour où il le fera passer par erreur.

**C'est l'élément à plus forte valeur du dépôt aujourd'hui**, et ce n'est pas un refactoring : les
workflows décrivent déjà ce qui devrait tourner. Il leur faut un `.gitlab-ci.yml` qui l'exécute, ou
un miroir push côté GitLab vers GitHub — et l'arbitrage entre les deux appartient au mainteneur.

---

## 2. Sécurité & Cryptographie — 8,6

Les vingt routes fermées à la passe précédente tiennent, et l'une d'elles n'est réellement vérifiée
que maintenant. **Un balayage des noms de routes — chaque littéral d'URL des tests confronté à
chaque mapping déclaré — a montré que le cas attestation visait
`/api/v1/attestation/scans/{id}` là où la route est `/api/v1/attestations/…`, au pluriel.** Cette
assertion renvoyait 404 parce que la route n'existait pas : le garde sur `AttestationController`
n'avait donc jamais été exercé. Il est correct ; le retirer fait maintenant échouer la suite.

C'est la troisième assertion de la semaine qui ne pouvait pas échouer, et les trois partagent une
forme qu'il vaut la peine de nommer : **une assertion négative ne vaut que ce que vaut la cible
qu'elle désigne.** Un `isNotFound()` sur un chemin mal orthographié, un
`getIndexInfo(unique = true)` face à un pilote qui ignore le drapeau, et un chemin de scorecard au
singulier — chacune passait pour une raison sans rapport avec ce qu'elle prétendait. Aucune n'a été
attrapée par une relecture ; les trois l'ont été par un second test ou un balayage mécanique.

Tout le reste se vérifie : Argon2id au minimum OWASP avec ses paramètres dans la chaîne PHC, les
drapeaux du bac à sable vérifiés sur le `HostConfig` remis au démon, l'isolation de l'agent par
ArchUnit, la chaîne d'audit testée en l'altérant, SCIM derrière un garde administrateur, et Vault
qui refuse de démarrer plutôt que de se rabattre sur une clé locale.

---

## 3. Qualité du Code & Architecture Logicielle — 8,2

**L'empreinte est enfin unique**, et la migration fusionne au lieu de supprimer : la ligne la plus
ancienne gagne, les enfants sont repointés avant que les perdants ne partent. La course qu'elle
ferme était réelle et silencieuse — le `toMap(…, (a, b) -> a)` de la réconciliation ne peut se
déclencher que sur une empreinte déjà dupliquée.

**Lecteurs de tables entières : de cinq à quatre.** L'inventaire des licences recevait un filtre et
l'ignorait dans chaque lecture, ce qui pesait plus qu'il n'y paraissait : une ligne de scan porte sa
charge SBOM entière, donc les licences d'un dépôt faisaient analyser celles du parc — et la
scorecard appelait la forme non filtrée à chaque requête.

Quatre subsistent, chacun justifié sur place : la vue d'ensemble sécurité a besoin de toutes les
cibles, le flux de renseignement réévalue le backlog par construction, et la scorecard portefeuille
lit l'inventaire complet parce que cet inventaire prend une cible et non une habilitation.

**La note baisse malgré tout, et la raison est la section 1.** 1250 tests, une campagne trois
moteurs, des planchers de couverture vérifiés par mutation et onze cas navigateur constituent une
suite solide à toute mesure — exécutée par une personne qui y pense. **Une qualité qui dépend de la
discipline est une qualité à point de défaillance unique**, et cette semaine a produit vingt-deux
commits de changements qu'aucune machine n'a jamais compilés.

---

## 4. Conformité Réglementaire & Standards — 8,8

Inchangée depuis la passe précédente et solide : six référentiels, la posture de la plateforme
plafonnant ce qu'elle peut revendiquer, SPDX tranché par la
[0016](../../architecture/fr/decisions/0016-no-spdx-document.md) plutôt que revendiqué, et les
exports agrégés désormais cadrés sur l'appelant.

Une conséquence de la section 1 a sa place ici plutôt que là-bas : **le récit chaîne
d'approvisionnement du CRA dépend d'un pipeline de release.** Des artefacts signés, un SBOM du jar
livré et une commande de vérification qu'un client peut exécuter, c'est précisément l'objet de
`CRA-ART10`. Le code qui produit les trois existe dans `release.yml`. Rien ne l'exécute.

---

## Recommandations

### 🔴 Maintenant

1. **Décider comment ce dépôt obtient un pipeline** — un `.gitlab-ci.yml` reprenant ce que les
   trois workflows décrivent, ou un miroir push GitLab vers GitHub pour que les existants se
   déclenchent. D'ici là, toute autre recommandation de tout rapport précédent est un conseil
   adressé à une machine qui n'écoute pas.
2. **Corriger les deux documents qui affirment le pipeline comme un fait.** Le *« le pipeline CI
   exécute automatiquement »* de la vue développement, et la commande de vérification de signature
   du `GETTING_STARTED`. Une instruction de vérification qui ne peut pas réussir est la pire espèce
   de documentation de sécurité.

### 🟠 Ensuite

3. **Faire du balayage des noms de routes un test.** Il a trouvé un garde jamais exercé, dans une
   suite écrite spécifiquement pour exercer des gardes. Un test vérifiant que chaque littéral
   d'URL de l'arbre de tests correspond à un mapping déclaré aurait attrapé les trois assertions
   vaines de la semaine.
4. **Donner une habilitation à la lecture des licences de la scorecard portefeuille** plutôt que
   de filtrer son résultat. C'est le dernier endroit où un filtre est appliqué après la requête
   plutôt que dedans.

### 🟡 Puis

5. **Couverture unitaire du frontal** : quinze specs pour vingt-sept pages.
6. **Réexaminer `GateService.openIssuesByTarget`** si la vue d'ensemble doit un jour passer à
   l'échelle — c'est justifié aujourd'hui parce que l'écran montre toutes les cibles, et cela
   cesse d'être vrai dès que l'écran est paginé.
