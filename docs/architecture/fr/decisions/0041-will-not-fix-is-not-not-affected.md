# 0041 — « Ne sera pas corrigé » n'est pas « non affecté » : un risque accepté reste exposé dans le VEX, et chaque format lit le même triage

**Date :** 2026-10-10 · **Statut :** acceptée · **S'appuie sur :** [0007](0007-none-is-not-an-empty-list.md) · **Décideur :** Laurent Boucher

*Proposée avant le code et acceptée le même jour : le propriétaire a tranché les deux questions qui
terminaient la proposition, et les réponses sont écrites dans la décision et rappelées à la fin.*

## Contexte

Vectispire signe trois formats VEX — CycloneDX, OpenVEX et CSAF — à partir d'un seul triage par
constat. Chaque déclaration qu'ils contiennent est une affirmation faite à un client sur un produit.
Plusieurs chemins y faisaient une affirmation que personne n'avait faite.

**Le refus d'un tracker devenait « non affecté ».** `TicketingWebhookService` lisait un ticket fermé en
*Won't Fix*, *Declined*, *Rejected*, *Risk Accepted* ou *Withdrawn* (et le `not_planned` de GitHub) et
mettait le constat en file comme `not_affected`, avec la justification `inline_mitigations_already_exist`.
Depuis que le webhook ne tranche plus sur-le-champ, la décision attend une approbation — mais
l'approbateur voit un statut et une justification que le tracker n'a jamais dits. Une fois la décision
approuvée, les documents signés affirment qu'une atténuation existe dans le produit. Le ticket disait
autre chose : l'équipe ne corrigera pas. La première affirmation dit que le produit n'est pas exposé ; la
seconde dit qu'il l'est, et que l'équipe le sait. Le `not_planned` de GitHub était en outre lu comme un
**faux positif**, avec `vulnerable_code_not_in_execute_path`, alors que c'est la seule façon de fermer
sans réaliser sur GitHub et que ce statut ne dit rien de l'atteignabilité.

**Une personne qui acceptait un risque n'avait pas non plus de statut honnête.** Le registre des
exceptions enregistrait une acceptation en `not_affected`, avec une justification que la personne
choisissait — dans un vocabulaire de cinq où aucune n'est vraie d'un produit exposé.

**Les formats ne lisaient pas le même triage.** Le générateur OpenVEX agrégé cherchait `false_positive`
et `accepted_risk`, deux statuts que `TriageStatus` n'a jamais eus : chaque `not_affected` approuvé
sortait `affected`, et un constat en revue ou en attente d'approbation aussi, là où CycloneDX disait
`in_triage` et CSAF `under_investigation`. L'export CSAF par cible n'avait pas de cas pour
`pending_approval` : un tel produit ne figurait dans aucune liste de statut. Le même constat était décrit
différemment dans chaque document signé.

**Et deux générateurs inventaient une justification.** Quand une ligne `not_affected` n'en portait
aucune, CycloneDX écrivait `vulnerable_code_not_in_execute_path` et CSAF
`vulnerable_code_cannot_be_controlled_by_adversary`, après avoir deviné d'après l'orthographe de ce qui
s'y trouvait. `Triage.decide` en exige une désormais, mais il existe des lignes antérieures et des lignes
importées. CycloneDX recevait de plus les libellés de justification d'OpenVEX, que son schéma n'accepte
pas, et répondait `will_not_fix` à chaque `not_affected` — rien à corriger dans un produit non affecté.

## Décision

### 1. Un cinquième statut : `will_not_fix`, réglé une fois accordé, avec une date de revue

`TriageStatus.WILL_NOT_FIX(true)` : *jugé applicable, et l'équipe a décidé de ne pas corriger* — un risque
accepté. Il règle comme `not_affected` et `fixed` : une fois accordé, il cesse de faire échouer une
barrière, comme une acceptation l'a toujours fait. Il passe donc par les quatre yeux comme eux
(`queueIfNotApprover` interroge `isSettled()`), et c'est une exception du registre — compté comme
accordé, revu, prolongé ou révoqué comme une levée. Deux règles dans `Triage.decide` :

- **une date de revue est exigée** — une acceptation sans date est celle que personne ne regarde plus ;
  elle revient en `under_review` par `expireStale` comme toute autre ;
- **aucune justification VEX n'est acceptée** — chacune des cinq dit pourquoi un produit n'est *pas*
  exposé.

La colonne (`varchar(30)`) le contient sans migration ; `settledWireNames()` l'inclut, puisqu'il se
dérive du drapeau.

### 2. Le refus d'un tracker est mis en file en `will_not_fix`, jamais en `not_affected`

Le webhook traduit *Won't Fix*, *Declined*, *Rejected*, *Risk Accepted*, *Withdrawn* et le `not_planned`
de GitHub en `WILL_NOT_FIX`, sans justification et avec une date de revue **proposée** à quatre-vingt-dix
jours — le tracker n'en donne aucune, et la personne qui accorde la demande fixe la sienne. Le
commentaire du ticket est gardé, avec l'auteur déclaré, comme donnée rapportée. La demande passe par
`triageView(…, false)` et attend une approbation : un tracker n'est pas un approbateur. **Seul un faux
positif explicite** — *False Positive*, *Cannot Reproduce*, *Not an Issue*, ou les mots « false positive »
dans un ticket GitHub ou GitLab — met encore en file un `not_affected` : là, le ticket affirme quelque
chose sur l'exposition.

**Un webhook ne déplace pas un constat qu'une personne a réglé** (`not_affected`, `will_not_fix`,
`fixed`). Il enregistre la parole du tracker dans le journal d'audit et ne change rien. Quand le tracker
contredit le statut réglé, l'entrée est `TRIAGE_CONTRADICTED_BY_TRACKER`, signalée au SIEM en
**`VECTI-SEC-037`** (issue `detected`) : l'un des deux se trompe, et seule une personne peut dire lequel.
Un tracker d'accord est journalisé, pas signalé.

### 3. Un statut, une déclaration, dans chaque format

| Triage | CycloneDX `analysis` | OpenVEX | CSAF `product_status` |
|---|---|---|---|
| `under_review`, `pending_approval` | `in_triage` | `under_investigation` | `under_investigation` |
| `affected` | `exploitable` | `affected` | `known_affected` |
| `will_not_fix` | `exploitable`, réponse `will_not_fix` | `affected`, `action_statement` « Will not fix: … » | `known_affected`, remédiation `no_fix_planned` |
| `not_affected` **avec** justification | `not_affected` + son orthographe CycloneDX | `not_affected` + la justification enregistrée | `known_not_affected` + la justification enregistrée en drapeau |
| `not_affected` **sans** justification (lignes anciennes) | `in_triage` | `under_investigation` | `under_investigation` |
| `fixed`, ou constat résolu | `resolved` | `fixed` | `fixed` |

**La justification n'est jamais inventée.** Une ligne `not_affected` sans justification n'est
l'affirmation de personne : elle sort donc *en cours d'analyse*. C'est la règle « absent n'est pas
vide » ([0007](0007-none-is-not-an-empty-list.md)), appliquée à une déclaration qui quitte la maison.
CycloneDX reçoit son propre vocabulaire — `code_not_present`, `code_not_reachable`,
`requires_environment`, `protected_by_mitigating_control` — apparié aux libellés OpenVEX comme
CycloneDX le publie.

La lecture vit à un seul endroit, `VexDisposition.of` dans `common.domain.vex`, qu'interrogent les cinq
chemins : les trois générateurs agrégés et les exports OpenVEX et CSAF par cible. Elle est dans `common`
plutôt que dans `exports`, puisque deux de ces chemins s'y trouvent. C'est d'avoir trois copies écrites à
la main qui a mené OpenVEX à lire des statuts inexistants.

### 4. Vérifiée par une seule table

`VexDispositionTest` vérifie chaque ligne du tableau, et qu'un constat résolu est corrigé quel que soit
son triage ; les tests d'export vérifient comment OpenVEX et CSAF écrivent un risque accepté, une levée
non justifiée et une demande en attente ; `TrackerRefusalRoutesTest` vérifie la traduction du webhook,
qu'une décision réglée reste, et l'entrée de contradiction. Un sixième statut ajoute une ligne au
tableau, pas une branche par générateur.

## Conséquences

- Les constats qu'un webhook a mis en `pending_approval` avant ce changement gardent leur demande
  `not_affected` + `inline_mitigations_already_exist`. **Avant de mettre à jour la production, relire la
  file** (`triaged_by like '%_webhook'`) et refuser celles qui viennent d'un refus. Pas de migration
  automatique : une personne a pu en approuver une en connaissance de cause.
- Une équipe qui ferme un ticket en *Won't Fix* voit une demande d'acceptation de risque, pas une levée.
  L'accorder retire le constat du chemin de la barrière jusqu'à sa date de revue, et les documents VEX
  continuent de dire que le produit est exposé.
- **Une demande en attente n'enregistre pas le statut demandé.** L'approbateur lit le commentaire et
  l'historique, puis choisit ; une acceptation et une levée en file se ressemblent dans le registre d'ici
  là. L'enregistrer demande une colonne, laissée pour le jour où le registre en aura besoin.
- L'interface gagne le statut (libellé, filtre, couleur, le dialogue qui exige une date de revue et
  masque la justification) dans les deux langues ; le guide du triage et la référence des exports VEX
  changent dans `docs/{en,fr}/` et `docs-site/`.

## Rejeté

- **Garder `not_affected`, avec une justification « neutre ».** Aucune des cinq ne dit « affecté,
  accepté ». En choisir une, c'est signer une fausseté.
- **Traduire le refus en `affected`, sans nouveau statut.** Le VEX perd la réponse due au client — *pas
  de correctif prévu* — et une acceptation ne pourrait plus être accordée du tout.
- **Laisser `will_not_fix` non réglé**, comme proposé. Honnête sur l'exposition, mais cela retirait la
  seule forme d'acceptation qu'avait le registre sans en offrir une autre : les équipes seraient revenues
  à `not_affected`.
- **Ignorer le refus.** La synchronisation depuis le tracker ne servirait plus à rien pour les refus,
  alors que l'information existe.

## Tranché le 2026-10-10

1. **L'acceptation de risque.** `will_not_fix` est réglé une fois accordé, avec une date de revue
   obligatoire — la forme honnête d'une acceptation. Il remplace le `not_affected` sous lequel une
   acceptation était enregistrée.
2. **Un webhook sur un constat réglé** enregistre sans le déplacer, et un désaccord est signalé au
   responsable sécurité (`VECTI-SEC-037`).
