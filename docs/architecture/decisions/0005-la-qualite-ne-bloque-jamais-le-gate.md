# 0005 — La qualité et la revue IA n'entrent dans aucun verdict

**Date :** 2026-08-07 · **Statut :** acceptée

## Contexte

Deux sources de constats ne sont pas de même nature que les autres.

L'**analyse de qualité** (Semgrep, catégories autres que `security`) produit des centaines
d'entrées sur un dépôt mature, en une après-midi, dès qu'on l'active.

La **revue IA** produit des constats à partir d'un modèle à qui l'on a donné le code du
dépôt — c'est-à-dire à qui un dépôt hostile peut dicter ce qu'il écrit.

Les deux alimentent le même backlog que les vulnérabilités, et le gate lisait tout.

## Décision

Ni l'un ni l'autre n'entre dans un verdict de gate. Le filtre est **dans
`policy_gate._is_considered`**, sur le type — et il n'y a **aucun drapeau de politique**
pour l'autoriser.

L'absence de drapeau est la décision, pas un oubli. Un drapeau ferait de « la qualité ne
bloque jamais » un mensonge : il suffirait que quelqu'un le coche pour que la garantie
disparaisse, et la phrase resterait écrite dans l'interface.

Une confiance déclarée `LOW` fait en outre descendre la sévérité d'un cran, ce qui place le
constat sous le seuil de gate par défaut : visible dans le backlog, incapable de bloquer.

## Ce qu'on a écarté

**Un drapeau `fail_on_quality` désactivé par défaut.** Voir ci-dessus.

**Supprimer les constats de faible confiance.** Un constat supprimé disparaît, puis
réapparaît en neuf le jour où la métadonnée de la règle change — en perdant son triage.
Descendre d'un cran donne exactement le comportement voulu sans mentir sur ce qui a été
trouvé.

**Abaisser la sévérité des constats de qualité pour qu'ils passent sous le seuil.** Ce
serait un mensonge sur la sévérité, et il se retrouverait dans l'export SARIF. Les exclure
est honnête ; les déguiser ne l'est pas.

## Conséquences

Le raisonnement est le même dans les deux cas, pris par deux bouts : **un gate qui rougit
le jour de la mise en service est un gate qu'on désactive à midi.** Ce qui bloque un build
doit être rare et défendable, sinon l'équipe apprend à contourner le mécanisme entier — et
elle contourne aussi les vulnérabilités critiques.

Le cloisonnement ne s'arrête pas au gate, et c'est la moitié invisible du travail. Chaque
endroit qui énumère les types de constats a dû en tenir compte : les compteurs en tête de
`/issues` (sinon « 1 847 problèmes à traiter » le jour de la mise en service), la sélection
des notifications (sinon un webhook annonçant des centaines de problèmes au premier scan),
la fenêtre de création de tickets (sinon la qualité l'affame indéfiniment) et l'export
SARIF, dont les `tags` déclaraient `security` en dur — **chaque constat de qualité serait
remonté dans GitHub code scanning comme une alerte de sécurité**.
