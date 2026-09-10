-- La durée de résolution, écrite au moment où elle est connue.
--
-- **Le tableau de bord calculait la moyenne de résolution en Java, sur toutes les issues fermées
-- du parc.** Pas par choix : la moyenne porte sur la différence entre deux horodatages, et aucune
-- requête de ce dépôt ne fait d'arithmétique de dates. Les trois moteurs l'écrivent de trois
-- façons, et une portabilité qu'on ne peut vérifier que sur un moteur n'en est pas une — c'est la
-- campagne nocturne qui l'apprendrait, après coup.
--
-- Une migration, elle, est **déjà écrite par dialecte** (décision 0013). C'est donc ici, et
-- uniquement ici, que l'arithmétique de dates a sa place : chaque fichier la dit dans sa propre
-- langue, une fois, et la colonne qui en résulte est un nombre. `avg` sur un nombre est portable
-- partout, et le calcul redescend dans la base au lieu de remonter en mémoire.
--
-- **`null` n'est pas zéro et ne doit jamais le devenir.** La colonne reste nulle pour une issue
-- encore ouverte, pour une issue sans première observation, et pour une issue dont la résolution
-- ne suit pas sa découverte — trois cas que le calcul en mémoire écartait déjà de sa moyenne. Les
-- confondre avec une résolution instantanée tirerait chaque moyenne vers le bas, ce qui est
-- exactement le sens qui flatte.
--
-- Le backfill applique le même écart aux lignes existantes, sous la même condition stricte
-- `resolved_at > first_seen_at`, pour qu'aucun chiffre affiché ne bouge le jour du déploiement.

-- SQLite range un `Instant` en millisecondes epoch — un `integer`, pas un texte ISO. Vérifié
-- plutôt que supposé : `strftime('%s', …)` rendrait null sur ces colonnes, sans erreur, et le
-- backfill n'aurait rempli aucune ligne sans que rien ne le signale.

alter table t_issue add column resolution_seconds bigint;

update t_issue
    set resolution_seconds = (resolved_at - first_seen_at) / 1000
 where resolved_at is not null
   and first_seen_at is not null
   and resolved_at > first_seen_at;
