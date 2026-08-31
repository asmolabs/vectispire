# Historique et preuves

L'historique est le registre de ce qui a été détecté et de ce qui a été décidé, par cible,
conservé pour le lecteur qu'il faudra convaincre après coup et qui n'était pas là.

## Ce qu'il contient

Par dépôt, chaque scan, avec :

- la **version du projet** que ce scan a lue ;
- les issues que ce scan a observées ;
- chaque **décision de triage** prise à leur sujet — de quel statut vers quel statut, par qui,
  avec quelle justification, et contre quelle version.

## Les issues que personne n'a triées

Une issue non triée est imprimée comme non triée, explicitement.

C'est un choix délibéré sur ce que signifie le silence. Un historique qui les omettrait
simplement laisserait « personne n'a regardé ceci » passer pour « quelqu'un a décidé que
c'était acceptable sans l'écrire ». Ce sont deux faits différents, et un auditeur est fondé à
les distinguer.

## Exporter

En **PDF** et en **CSV**.

Le PDF est écrit pour une personne : un auditeur, l'équipe sécurité d'un client, un assureur.
Le CSV est destiné à l'analyse que quelqu'un veut mener lui-même.

## Voir aussi

- [Constats et triage](issues.md) — comment les décisions sont consignées en premier lieu.
- [Journal d'audit](../administration/audit-log.md) — la chaîne infalsifiable en dessous.
- [Conformité](compliance.md) — l'évaluation par référentiel que ce registre soutient.
