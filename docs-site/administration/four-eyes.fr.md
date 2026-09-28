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

Il refuse aussi tant que **moins de deux comptes actifs peuvent publier un modèle de checklist** — le
gouverneur de la plateforme, un administrateur ou un CISO. Sous les quatre yeux, une version de modèle
est publiée par quelqu'un d'autre que son auteur, et l'écrire demande le même rôle : avec un seul tel
compte, chaque brouillon pourrait être importé et aucun jamais publié. Créez-en d'abord un second.
[Modèles de checklists](checklist-templates.fr.md#4-publier) décrit ce qu'on dit à l'auteur d'un
brouillon quand le serveur refuse qu'il le publie lui-même.

Et il refuse tant que **moins de deux comptes actifs peuvent approuver** — un administrateur, un CISO
ou un référent sécurité. Sous les quatre yeux, la checklist d'un projet est approuvée par un
approbateur qui n'en a rien écrit — qui ne l'a pas ouverte, n'a répondu à ni confirmé aucune ligne,
n'a joint ni retiré aucune preuve, ni ne l'a soumise — et ce sont souvent les approbateurs qui
remplissent les checklists : avec un seul, ce qu'il aurait répondu pourrait être soumis et jamais
approuvé. Créez-en d'abord un second.

L'**éteindre** reste possible dans tous les cas : c'est l'activation qui demande un second.

## Approuver une checklist

La checklist d'un projet est approuvée par un approbateur. Double contrôle activé, le serveur refuse
l'approbation par **n'importe lequel des auteurs de la révision** — le compte qui l'a ouverte, a
répondu à, reporté ou confirmé une ligne, joint ou retiré une preuve, ou l'a soumise, comparé comme
compte et comme nom. Le refus est inscrit au journal d'audit et envoyé au SIEM (`VECTI-SEC-026`) ;
une approbation indique si la règle s'appliquait. Double contrôle éteint, un approbateur peut
approuver ce qu'il a écrit.

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
- [Modèles de checklists](checklist-templates.fr.md) — une version de modèle publiée par quelqu'un d'autre que son auteur.
- [SIEM](../integrations/siem.fr.md#catalogue-des-evenements) — une checklist approuvée (`VECTI-SEC-025`), une approbation refusée ou une checklist renvoyée (`VECTI-SEC-026`).
- [Journal d'audit](audit-log.fr.md) — où chaque décision et chaque changement de réglage sont inscrits.
