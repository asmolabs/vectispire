# 0002 — La base de données porte la file

**Date :** 2026-08-08 · **Statut :** accepté

## Contexte

La file d'analyses était un `ThreadPoolExecutor` au niveau du module. Trois choses en découlaient,
et toutes trois étaient des défauts plutôt que des compromis :

* **Un redémarrage perdait le travail en cours.** Une analyse en file n'existait que dans le tas
  d'une JVM : rien n'enregistrait qu'elle avait été demandée.
* **Une seconde instance ne pouvait pas aider.** Deux control planes avaient chacun leur exécuteur
  et leur propre idée de ce qui était en attente.
* **Un agent distant ne pouvait pas exister du tout.** Il n'y avait rien à réclamer.

## Décision

**Une analyse est une ligne.** La déclencher insère dans `t_scan` avec le statut `pending` et rend
la main immédiatement ; une boucle de travail la réclame et l'exécute. La réclamation est
transactionnelle — `SELECT … FOR UPDATE SKIP LOCKED` là où le moteur le propose, une mise à jour
conditionnelle sinon — et porte un **bail** : `claimed_by`, `claimed_at`, `lease_expires_at`,
`attempts`.

## Conséquences

**La file survit à tout ce à quoi le processus ne survit pas.** Un plantage en cours d'analyse
laisse une ligne dont le bail expire, et le tic suivant la reprend avec `attempts` incrémenté. Rien
n'est perdu et rien n'est réessayé indéfiniment.

**C'est ce qui rend les agents possibles**, et la [0003](0003-long-polling-for-agents.md) s'y
appuie : un agent réclame en HTTP les mêmes lignes que le worker intégré réclame en JDBC. Il y a une
file et une règle de réclamation, non un chemin local et un chemin distant qui dérivent.

**Le bail est demandé à l'intérieur de la transaction d'écriture, jamais avant.** Un worker qui
vérifierait son bail puis écrirait vérifierait un fait qui peut expirer entre les deux instructions
— et la fenêtre est exactement le moment où une analyse lente est reprise par un autre.

**Aucun verrou de ligne, et cela a été mesuré plutôt que supposé.** `SELECT … FOR UPDATE SKIP
LOCKED` avec un `ORDER BY … LIMIT` prend des verrous de clé suivante sur MySQL : il a produit
« Deadlock found when trying to get lock » sous huit réclamants simultanés, et il compte les lignes
sautées dans la `LIMIT`, de sorte qu'un réclamant dont tous les candidats sont verrouillés revient
bredouille alors qu'il reste des lignes — et la file cesse de s'écouler. La prise conditionnelle qui
l'a remplacé est un chemin unique sur tous les moteurs. Les deux défauts ont été trouvés en lançant
dix réclamants simultanés contre un serveur réel ; aucun n'est visible sur SQLite ni à la lecture
attentive.

**Un lot court est une caractéristique de débit, pas un défaut de justesse.** Un worker qui demande
deux analyses peut en obtenir une. Aucune ligne n'est jamais remise à deux workers — c'est la
propriété que la campagne vérifie — et le reste part au tic suivant.

**Une table plutôt qu'un courtier.** Vectispire exige déjà une base et n'exige pas de serveur de
file ; en ajouter un serait une seconde chose à exploiter, sauvegarder et sécuriser pour une charge
qui se mesure en analyses par heure. Le même raisonnement a fait de `leader_lease` une table plutôt
qu'un verrou consultatif : elle est **observable**, et un exploitant demandant « qui tient le tic »
peut y répondre par une requête.
