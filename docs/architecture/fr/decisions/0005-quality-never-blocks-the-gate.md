# 0005 — La qualité ne bloque jamais la gate

**Date :** 2026-08-11 · **Statut :** accepté

## Contexte

Semgrep produit deux sortes de constats en une passe. Le `metadata.category` de chaque règle
tranche : `security` devient un constat `sast`, tout le reste devient `quality`. La seconde sorte
arrive en volume — style, complexité, code mort — sur n'importe quel dépôt qui n'a pas déjà été
passé au peigne de ce jeu de règles précis.

Une gate qui échoue là-dessus est une gate qu'on éteint. Pas qu'on discute : qu'on éteint, une
fois, par celui qui essaie de livrer un vendredi, et qu'on ne rallume jamais. Les règles de sécurité
partent avec, parce qu'elles étaient derrière le même drapeau.

La revue IA a un problème différent appelant la même réponse. Un modèle local reçoit le code source
du dépôt analysé, et un dépôt hostile peut orienter un modèle à qui l'on a remis sa source. Un
`critical` inventé ferait échouer la construction de quelqu'un sur la parole d'un texte écrit par
l'arbre audité.

## Décision

**Les constats de qualité ne peuvent jamais atteindre un verdict de gate**, et c'est une propriété
du type de constat plutôt qu'un drapeau de politique :
[`FindingType`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/issues/FindingType.java)
déclare `QUALITY` en `GateParticipation.NEVER`, de sorte qu'aucune configuration ne peut l'y
admettre.

**La revue IA est `ON_REQUEST`** — suivie dans le backlog, absente du verdict tant qu'un exploitant
n'a pas posé `include_ai_review`.

Tout le reste est `ALWAYS` : vulnerability, secret, IaC, license, EOL, sast.

## Conséquences

**Un nouveau type de constat doit déclarer où il se situe**, parce que l'énumération l'exige. C'est
le mécanisme qui empêche cette décision de se déliter : ajouter un type sans penser à la gate n'est
pas exprimable.

**La distinction n'est pas « important » contre « pas important ».** Les constats de qualité sont
suivis, comptés, affichés et exportables. Ils sont exclus d'une conséquence précise — faire échouer
une construction — parce que c'est cette conséquence qui pousse les gens à désactiver le contrôle
qui la porte.

**Les deux sortes viennent de la même exécution**, elles entrent donc ensemble dans la liste des
types analysés. Une passe n'ayant produit que des constats de qualité compte tout de même comme un
SAST ayant tourné, et la [0007](0007-none-is-not-an-empty-list.md) s'y applique normalement.

**L'exclusion de la revue IA est un contrôle de sécurité, pas un jugement de qualité.** C'est
pourquoi l'invite encadre l'échantillon d'un délimiteur explicite et demande au modèle de *signaler*
une tentative d'injection plutôt que d'y obéir : c'est une atténuation, et si son verdict ne bloque
rien par défaut, c'est qu'une atténuation n'est pas une frontière de confiance.
