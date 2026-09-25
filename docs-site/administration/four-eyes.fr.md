# Double validation

Un contrôle qui fait qu'une décision de triage demande deux personnes : une qui la propose, une qui
l'approuve.

Il s'active dans **Réglages → Triage VEX et approbation**. Éteint, la décision de quiconque peut
trier se règle immédiatement. Allumé, la même décision entre dans une file d'approbation et seul un
approbateur la clôt.

## À quoi il sert

Une décision de triage n'est pas une note. Un `not_affected` avec sa justification part tel quel
dans les documents CycloneDX, OpenVEX et CSAF signés remis aux clients. Ce contrôle existe pour que
l'affirmation la plus forte que ce produit sache publier sur une vulnérabilité ne soit pas le clic
d'une seule personne.

## Qui approuve, et qui ne peut pas

L'approbation appartient aux rôles qui répondent du parc. Le **gouverneur de la plateforme** — le
compte d'amorçage — en est délibérément **exclu**, et ne peut pas trier du tout.

C'est la partie qui mérite d'être comprise, parce que ce n'est pas un oubli. Le gouverneur est le
seul rôle qui puisse éteindre ce contrôle. S'il pouvait aussi décider sous la règle, le contrôle
serait contournable par une seule personne en trois gestes : éteindre, régler seul, rallumer, une
entrée d'audit pour toute trace. Retirer le droit d'approuver n'aurait rien fermé — le service règle
la décision de tout le monde quand le réglage est éteint. Ce qui le ferme est qu'**aucun rôle ne
détient les deux moitiés** : celui qui peut lever la règle ne peut pas agir sous elle.

## L'activer demande qu'une seconde personne existe

Si aucun compte actif ne peut approuver, le serveur refuse l'activation. Sans ce garde, l'allumer là
où il n'y a pas d'approbateur met chaque décision dans une file que personne ne peut vider — un
contrôle qui bloque au lieu de contrôler, et dont la panne ne se voit qu'au premier triage.

Créez d'abord un administrateur, un CISO ou un référent sécurité.

L'**éteindre** reste possible dans tous les cas : c'est l'activation qui demande un second.

## Les décisions venues d'un traqueur

Un webhook de ticket peut rapporter une décision de triage, et cette décision ne se règle jamais
d'elle-même — quoi que dise le traqueur. La route ne peut pas porter de session : elle n'accepte
rien tant qu'aucun secret de webhook n'est configuré ; une fois qu'il l'est, ce qui y entre part
encore en approbation — le secret prouve que le traqueur a envoyé l'appel, pas que quelqu'un a
regardé la vulnérabilité — et l'entrée d'audit inscrit l'intégration comme auteur, le nom revendiqué
restant à côté comme une donnée rapportée.

## À lire aussi

- [Constats et triage](../guide/issues.fr.md) — là où une décision se propose.
- [Utilisateurs et équipes](users-and-teams.fr.md) — les rôles et ce que chacun peut faire.
- [Journal d'audit](audit-log.fr.md) — où chaque décision et chaque changement de réglage sont inscrits.
