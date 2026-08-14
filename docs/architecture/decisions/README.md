# Registre des décisions

Une page par décision structurante : ce qui a été décidé, ce qui a été écarté, et ce que
ça coûte. Ce sont les choix qu'on regretterait d'avoir à re-débattre, ou qu'on referait
mal en ne connaissant pas l'alternative déjà essayée.

| # | Décision | Date | Statut |
|---|---|---|---|
| [0001](0001-couche-de-scan-pluggable.md) | La couche de scan est pluggable derrière `ScannerEngine` | 2026-07-28 | acceptée |
| [0002](0002-la-base-porte-la-file.md) | La base porte la file, pas un broker | 2026-08-06 | acceptée |
| [0003](0003-long-polling-pour-les-agents.md) | Les agents parlent en long-polling HTTP, jamais à la base | 2026-08-06 | acceptée |
| [0004](0004-sqlite-et-postgresql-seulement.md) | Deux moteurs de base : SQLite et PostgreSQL | 2026-08-10 | **remplacée par [0008](0008-postgresql-et-mysql.md)** |
| [0005](0005-la-qualite-ne-bloque-jamais-le-gate.md) | La qualité et la revue IA n'entrent dans aucun verdict | 2026-08-07 | acceptée |
| [0006](0006-regles-semgrep-ecrites-ici.md) | Les règles Semgrep sont écrites ici, pas redistribuées | 2026-08-07 | acceptée |
| [0007](0007-none-n-est-pas-une-liste-vide.md) | Un analyseur qui échoue renvoie `None`, jamais `[]` | 2026-08-07 | acceptée |
| [0008](0008-postgresql-et-mysql.md) | Deux moteurs de base : PostgreSQL et MySQL | 2026-08-14 | acceptée |

## Les règles du registre

**Une décision est immuable.** Elle décrit ce qui a été décidé à une date, avec ce qu'on
savait alors. Quand elle ne tient plus, on en écrit une nouvelle qui la remplace et la
cite, et l'ancienne passe en statut *remplacée* — sans que son texte change.

C'est précisément ce que les deux anciens fichiers `ADR-001` et `ADR-002` ne faisaient
pas : ils étaient amendés section après section jusqu'à ce que plus personne ne puisse
dire, en les lisant, ce qui était encore vrai.

**Ce qui n'a pas d'alternative n'est pas une décision.** Utiliser SQLAlchemy pour parler à
une base n'a pas sa page ici. Une décision mérite le registre quand quelqu'un aurait pu
choisir autrement, et le referait s'il ne savait pas pourquoi.

**L'alternative écartée est la moitié qui compte.** Un lecteur qui ne trouve pas
l'alternative supposera qu'elle n'a pas été envisagée, et la proposera. La section « ce
qu'on a écarté » n'est pas de la politesse : c'est ce qui empêche le débat de recommencer.
