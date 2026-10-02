# Historique et preuves

L'historique est le registre de ce qui a été détecté et de ce qui a été décidé, par cible,
conservé pour le lecteur qu'il faudra convaincre après coup et qui n'était pas là.

## Ce qu'il contient

Par dépôt, chaque scan, avec :

- la **version du projet** que ce scan a lue ;
- les issues que ce scan a observées ;
- chaque **décision de triage** prise à leur sujet — de quel statut vers quel statut, par qui,
  avec quelle justification, et contre quelle version.

## Les réouvertures

Quand une analyse (ou un import) retrouve une issue résolue, l'issue est rouverte, et
l'historique le dit sur une ligne à part : *rouvert — retrouvé par une analyse ou un import,
résolu depuis le* jour où sa résolution avait commencé. Une décision `fixed` que ce retour
contredit apparaît comme quittée pour *en revue* ; un jugement qui y survit — *non affecté* —
apparaît comme maintenu. Personne n'est nommé, parce que personne n'a décidé : la ligne est un
fait sur l'issue, pas une décision, et le compte des décisions de la cible ne l'inclut pas. Le
CSV la porte dans `decision_origin` (`reopen`) et dans sa dernière colonne,
`decision_previous_resolved_at`.

Une réouverture antérieure à cette version n'a laissé aucune ligne, et la résolution qu'elle a
close n'est pas connue.

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
