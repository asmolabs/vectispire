-- La clause de barrière qui refuse un verdict rendu sans examen.
--
-- **Une cible qu'aucune règle n'atteint ne produit aucun constat de code, et rien ne passe une
-- politique aussi bien que rien.** C'est le vert que ce produit existe pour distinguer d'un vert
-- propre. Le bandeau de couverture le dit désormais sur les écrans où l'absence trompe ; cette
-- colonne est la seconde moitié : le déploiement qui le veut peut faire *refuser* le verdict au
-- lieu de le commenter.
--
-- **`default false`, et c'est la décision plutôt que le réglage.** La valeur stricte est l'autre,
-- mais l'activer pour tout le monde ferait échouer chaque build existant au premier déploiement,
-- sur une condition dont personne n'a été informé. On ne pose pas un refus avant d'avoir rendu la
-- cause visible — et la rendre visible était le commit précédent.
--
-- `not null` avec valeur par défaut : les lignes déjà stockées reçoivent le comportement qu'elles
-- avaient, ce qui est la seule migration correcte pour un drapeau que personne n'a encore choisi.

alter table t_gate_policy add column fail_on_uncovered_languages boolean not null default false;
