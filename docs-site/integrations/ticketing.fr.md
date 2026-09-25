# Tickets

Vectispire ouvre des tickets dans **GitLab**, **GitHub**, **Jira** ou **ServiceNow** — un par
problème qui ferait échouer une construction.

## Un seul seuil, défini une fois

La création de tickets utilise **la même politique de barrière** que la barrière CI.

C'est la décision de conception qui vaut d'être comprise. Un seuil de ticket séparé
signifierait deux barres à tenir alignées, et elles dériveraient : les équipes finiraient avec
des tickets pour des choses qui ne font pas échouer leur construction, ou avec une construction
rouge sans ticket derrière. Une politique, une réponse. Voir
[Politiques de barrière](../administration/gate-policies.md).

## Aucun doublon, jamais

La référence du ticket est conservée **sur l'issue**.

Ainsi, une panne du tracker donne lieu à une reprise plutôt qu'à une perte, et la reprise
retrouve la référence existante sans ouvrir un second ticket. La même issue vue sur cinquante
scans nocturnes consécutifs, c'est un ticket.

## Configurer

Sous [Réglages](../administration/settings.md) : le type de tracker, son URL, le projet ou la
cible, et un jeton.

Donnez au jeton la portée la plus étroite permettant de créer et de lire des tickets dans le
projet visé. Il est stocké chiffré avec votre `ENCRYPTION_KEY`, et son stockage est refusé
avant que cette clé existe.

## Ce qui atterrit dans le ticket

De quoi agir sans ouvrir Vectispire : le composant et sa version, l'identifiant, la gravité,
l'existence d'un correctif, les statuts EPSS et KEV, et un lien de retour vers l'issue.

## Boucler la boucle

Fermer le ticket dans le tracker ne résout pas l'issue dans Vectispire — `state` n'est écrit
que par le pipeline, à partir de ce que les scanners observent. Corrigez la dépendance, et le
scan suivant la résout.

L'autre sens est automatique : quand un scan résout une issue, Vectispire ferme le ticket qu'il
avait ouvert pour elle. Chaque traqueur est appelé avec le verbe que son API route pour une mise à
jour — `PUT` sur GitLab, `PATCH` sur GitHub et ServiceNow, une transition sur Jira — celle que le workflow du ticket propose
vers un statut de catégorie *done*, demandée à Jira à chaque fois plutôt que supposée. ServiceNow
désigne un enregistrement par son `sys_id`, alors que la référence gardée par Vectispire est le
numéro d'incident que les gens lisent (`INC0012345`) : le numéro est donc d'abord recherché dans la
table des incidents, et le compte ServiceNow a besoin du droit de **lecture** sur `incident` en plus
de l'écriture.

Si elle ne va pas être corrigée, c'est une [décision de triage](../guide/issues.md), avec une
justification et de préférence une date de réexamen.
