# Journal d'audit

Un registre immuable et chaîné par empreintes de ce qui a été fait, et par qui.

!!! info "Qui peut le lire"
    Les administrateurs, le CISO, et le rôle **Auditeur** — qui lit cette page et ne change rien,
    nulle part. Avant que ce rôle existe, ouvrir le journal d'audit à quelqu'un revenait à lui
    donner aussi le droit de réécrire la politique qu'il venait vérifier.

## Pourquoi une chaîne

Chaque entrée est chaînée à la précédente, si bien qu'une entrée ne peut être modifiée ou
retirée sans rompre la chaîne à partir de ce point.

Une simple table d'audit enregistre ce qui s'est passé, à condition que personne disposant d'un
accès à la base n'ait voulu lui faire dire autre chose. Une chaîne rend l'altération
**manifeste**, ce qui est une affirmation matériellement différente — et c'est celle sur
laquelle un auditeur, un assureur ou l'équipe sécurité d'un client s'interroge réellement.

L'écran de vérification contrôle la chaîne et vous dit où elle rompt.

## Le miroir

```bash
VECTISPIRE_AUDIT_MIRROR=/var/log/vectispire/audit.jsonl
```

Chaque entrée est ajoutée comme une ligne JSON, **hors de la base de données qu'elle surveille**.

C'est ce qui referme l'écart restant. Une chaîne à l'intérieur de la base détecte l'altération
par quiconque ne peut pas réécrire la chaîne entière ; une seconde copie à l'extérieur détecte
l'altération par quelqu'un qui le peut. Pointez-la vers un chemin expédié vers un magasin de
journaux où vous pouvez ajouter sans pouvoir éditer.

Désactivé signifie que le journal n'a qu'une copie — et l'écran de vérification le dit, plutôt
que de laisser entendre une garantie qu'il ne peut pas donner.

## Quoi vérifier, et quand

- Après tout changement de privilège inattendu.
- Avant d'exporter des [preuves de conformité](../guide/compliance.md).
- Périodiquement, pour que la réponse ne soit pas cherchée pour la première fois le jour où
  elle compte.

## Voir aussi

[Utilisateurs et équipes](users-and-teams.md) ·
[Historique et preuves](../guide/history.md) — le registre de triage, qui est un autre document
pour une autre question.
