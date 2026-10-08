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

## Le webhook entrant {#inbound-webhook}

Un tracker peut aussi rappeler Vectispire, sur `POST /api/v1/tickets/webhook/{provider}` —
`gitlab`, `github`, `jira` ou `servicenow`. Quand un ticket que Vectispire connaît par sa
référence est fermé comme faux positif ou comme non corrigé, l'appel **propose** une décision
`not_affected` sur l'issue ; toute autre mise à jour est seulement tracée dans le journal d'audit.

**Il est refusé tant qu'aucun secret n'est posé.** La route est la seule ouverte sans compte — le
tracker ne porte pas de session —, le secret est donc toute son authentification. Tant que
**Paramètres → Tickets → Secret du webhook entrant** est vide, chaque appel reçoit `403` et
*« The ticket webhook is not configured on this instance »*, ce que montre le journal de livraison
du tracker. Posez le secret, puis la même valeur dans le tracker, présentée comme ce tracker
présente un secret :

| Tracker | En-tête | Ce qu'il porte |
|---|---|---|
| GitLab | `X-Gitlab-Token` | le secret lui-même, le champ *Secret token* de GitLab |
| GitHub | `X-Hub-Signature-256` | `sha256=` suivi du HMAC-SHA256 du corps brut, le champ *Secret* de GitHub |
| Jira, ServiceNow | `X-Vectispire-Token` | le secret lui-même — aucun des deux n'a de convention, cet en-tête est donc accepté pour ces deux-là et aucun autre |

Un en-tête faux ou absent reçoit `401`, sans dire quel en-tête était attendu. Un secret enregistré
qu'aucune clé configurée ne déchiffre refuse de la même façon : posez-le de nouveau.

**Une livraison n'est traitée qu'une fois.** L'empreinte de chaque corps accepté est gardée trente
jours ; le même corps reçu de nouveau dans cette fenêtre — un rejeu, ou la redélivrance du tracker
lui-même — reçoit `200` *« Delivery already processed »* et ne change rien.

**Une décision est mise en file, jamais appliquée.** L'issue passe en `pending_approval` avec le
statut proposé et sa justification, et reste *en cours de revue* dans les documents VEX exportés
jusqu'à ce qu'une seconde personne l'approuve sous le [principe des quatre yeux](../administration/four-eyes.md).
L'auteur enregistré est l'intégration (`GITLAB_webhook`, …) ; le nom que rapporte le tracker va
dans le commentaire, comme donnée rapportée et non comme identité.

Les livraisons sont limitées par adresse d'appelant (`VECTISPIRE_WEBHOOK_REQUESTS_PER_WINDOW`, voir
[Configuration](../reference/configuration.md)).
