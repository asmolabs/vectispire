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

Il couvre les trois statuts qui **règlent** une issue — qui la sortent du chemin de la barrière :
`not_affected`, `will_not_fix` (*Ne sera pas corrigé — risque accepté*) et `fixed`. Un risque accepté
n'affirme pas que le produit est sûr — les documents continuent de dire qu'il est exposé, sans
correction prévue —, mais il cesse de faire échouer les builds jusqu'à sa date de réexamen : c'est une
décision du même poids qu'une levée ([décision 0041](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0041-will-not-fix-is-not-not-affected.md)). Sous la règle, la demande de quelqu'un qui
ne peut pas approuver est mise en file en `pending_approval`, compte toujours à la barrière, et se lit
*en cours d'investigation* dans tous les formats VEX jusqu'à ce qu'elle soit accordée.

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
[Modèles de checklists](checklist-templates.fr.md#5-publier) décrit ce qu'on dit à l'auteur d'un
brouillon quand le serveur refuse qu'il le publie lui-même.

Et il refuse tant que **moins de deux comptes actifs peuvent approuver** — un administrateur, un CISO
ou un référent sécurité. Sous les quatre yeux, la checklist d'un projet est approuvée par un
approbateur qui n'en a rien écrit — qui ne l'a pas ouverte, n'a répondu à ni confirmé aucune ligne,
n'a joint ni retiré aucune preuve, ni ne l'a soumise — et ce sont souvent les approbateurs qui
remplissent les checklists : avec un seul, ce qu'il aurait répondu pourrait être soumis et jamais
approuvé. Créez-en d'abord un second.

Le même décompte couvre les **plugins de rapport** : sous les quatre yeux, le manifeste d'un plugin de
rapport est approuvé par une personne qui écrit la gouvernance autre que le gouverneur qui l'a
enregistré, si bien que les deux comptes qui permettent de publier des modèles permettent aussi
d'approuver des manifestes ([Plugins de rapport](report-plugins.fr.md#enregistrer-approuver-activer)).

L'**éteindre** reste possible dans tous les cas : c'est l'activation qui demande un second.

## Approuver une checklist

La checklist d'un projet est approuvée par un approbateur. Double contrôle activé, le serveur refuse
l'approbation par **n'importe lequel des auteurs de la révision** — le compte qui a ouvert une
checklist neuve, donné une réponse qu'elle contient, confirmé une ligne reportée, joint ou retiré une
preuve, ou l'a soumise, comparé comme compte et comme nom. Reporter des réponses, en rouvrant ou en
changeant de version, n'est pas écrire. Le refus est inscrit au journal d'audit et envoyé au SIEM (`VECTI-SEC-026`) ;
une approbation indique si la règle s'appliquait. Double contrôle éteint, un approbateur peut
approuver ce qu'il a écrit.

## Les décisions venues d'un traqueur

Un webhook de ticket peut rapporter une décision de triage, et cette décision ne se règle jamais
d'elle-même — quoi que dise le traqueur. La route ne peut pas porter de session : elle n'accepte
rien tant qu'aucun secret de webhook n'est configuré ; une fois qu'il l'est, ce qui y entre part
encore en approbation — le secret prouve que le traqueur a envoyé l'appel, pas que quelqu'un a
regardé la vulnérabilité — et l'entrée d'audit inscrit l'intégration comme auteur, le nom revendiqué
restant à côté comme une donnée rapportée. Le refus d'un traqueur (*Won't Fix*, le *not planned*
de GitHub…) arrive comme une demande de `will_not_fix`, un faux positif explicite comme une demande
de `not_affected` ; l'approbateur choisit le statut et la date de réexamen. Et une issue qu'une
personne a déjà réglée ne bouge pas du tout sur un ticket : la parole du traqueur est inscrite, et
signalée comme `VECTI-SEC-037` quand elle contredit la décision
([Tickets](../integrations/ticketing.md#inbound-webhook)).

## À lire aussi

- [Constats et triage](../guide/issues.fr.md) — là où une décision se propose.
- [Utilisateurs et équipes](users-and-teams.fr.md) — les rôles et ce que chacun peut faire.
- [Modèles de checklists](checklist-templates.fr.md) — une version de modèle publiée par quelqu'un d'autre que son auteur.
- [Checklists de sécurité](../guide/security-checklists.fr.md#5-approuver) — la checklist d'un projet approuvée par quelqu'un qui n'en a rien écrit.
- [SIEM](../integrations/siem.fr.md#catalogue-des-evenements) — une checklist approuvée (`VECTI-SEC-025`), une approbation refusée ou une checklist renvoyée (`VECTI-SEC-026`).
- [Journal d'audit](audit-log.fr.md) — où chaque décision et chaque changement de réglage sont inscrits.
