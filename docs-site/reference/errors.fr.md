# Erreurs de l'API

Chaque refus de l'API REST est un document « problem » au sens de la
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457). Lisez `detail` : c'est la phrase écrite pour
l'auteur de la requête.

```json
{
  "title": "Bad Request",
  "status": 400,
  "detail": "Scheme \"ftp\" is not allowed. Expected https, ssh or git.",
  "instance": "/api/v1/repositories"
}
```

| Membre | Toujours présent | Sens |
|---|---|---|
| `status` | oui | Le statut HTTP, répété. |
| `title` | oui | La formule standard du statut. Pas faite pour être affichée seule. |
| `detail` | oui | Ce qui ne va pas, en des termes faits pour être affichés tels quels. |
| `instance` | oui | Le chemin demandé. |
| `retryAfterSeconds` | sur un 429 | Le temps d'attente. L'en-tête `Retry-After` porte le même nombre. |
| `correlationId` | sur un 500 | Une référence à transmettre à votre administrateur ; elle figure aussi dans `detail`. |
| `type` | sur certains 409 | `urn:vectispire:problem:<cause>`, qui nomme la raison — voir [Causes d'un 409](#causes-dun-409). Absent, il vaut `about:blank`. |
| `integration` | avec `integration-disabled` ou `integration-in-use` | La clé de l'intégration désactivée, ou qui n'a pas pu l'être, par exemple `forge.gitlab` ou `siem.syslog_tls`. |

Le type de contenu est `application/problem+json`, y compris pour une requête que le serveur web
refuse avant que l'application ne la voie : une URL que le pare-feu de sécurité rejette — `//`, un
`..` encodé, un `;` — et une URL que le conteneur de servlets ne peut pas décoder, comme un `%`
isolé ou un `/` encodé. Les deux sont un 400 dont le `detail` dit quel genre d'URL a été refusé ;
aucune n'est une page HTML, et aucune ne nomme le serveur ni sa version. Une exception demeure :
une défaillance levée avant qu'une route ne soit atteinte reçoit de la page d'erreur les mêmes
membres, en `application/json` sauf si le client demande `application/problem+json` dans
`Accept`.

## Ce que signifie chaque statut

| Statut | Quand |
|---|---|
| **400** | La requête est mal formée ou une valeur y est refusée : un champ manquant, une URL dont le schéma n'est pas admis, un paramètre du mauvais type, un corps qui n'est pas du JSON. Corrigez-la et renvoyez-la. |
| **401** | Pas d'identifiant, ou un identifiant invalide. Reconnectez-vous, ou vérifiez la clé. |
| **403** | L'identifiant est valide et n'autorise pas ceci : le rôle ne le permet pas, un changement de mot de passe est dû, ou la clé ou l'identifiant d'agent n'est pas accepté sur cette route. Le détail ne nomme pas les rôles qui le permettraient. |
| **404** | La route n'existe pas, ou ce que le chemin désigne n'existe pas — **ou existe et vous n'avez pas à le voir**. Les deux se lisent pareil, dans les mêmes mots, à dessein : une réponse différente confirmerait l'existence d'un dépôt, d'un scan ou d'un constat qui ne vous a pas été confié. |
| **405 / 406 / 415** | Mauvaise méthode, un `Accept` auquel la route ne sait pas répondre, un corps dans un type de média que la route ne lit pas. |
| **409** | La requête entre en conflit avec l'état actuel et peut réussir plus tard telle quelle : un scan déjà en file, une solution qui contient encore des projets, une revue OWASP qui ne peut pas encore tourner, une intégration désactivée. |
| **412** | Il manque au déploiement quelque chose qu'un exploitant règle : la clé de chiffrement, un secret qu'un agent ne peut pas recevoir. |
| **413** | Le corps dépasse ce que la route accepte. Le détail donne le plafond. |
| **422** | Une destination refusée par la politique de sortie. |
| **429** | Trop de tentatives depuis cette adresse ou avec cette clé. Attendez `retryAfterSeconds`. |
| **500** | Une défaillance pour laquelle personne n'a écrit de phrase. Le détail dit seulement qu'elle s'est produite et cite un `correlationId` ; l'erreur complète est dans le journal du plan de contrôle, sous cette référence. |
| **503** | Passager : trop de connexions attendent leur second facteur. Réessayez dans quelques minutes. |

## Causes d'un 409

Quand une route refuse pour plusieurs raisons qui appellent des gestes différents, le `type` du
problème nomme la cause, pour qu'un client les distingue sans lire la phrase, qui peut changer.
Chaque route énonce ses causes dans la [référence de l'API REST](https://github.com/asmolabs/vectispire/blob/main/docs/fr/api/rest_api_reference.md).
Deux concernent les intégrations — la première sur plusieurs routes, la seconde sur la bascule du gouverneur :

| `type` | Quand | Membres |
|---|---|---|
| `urn:vectispire:problem:integration-disabled` | Le geste a besoin d'une intégration — un type de forge, un transport SIEM, un fournisseur d'IA, un canal de notification, un gestionnaire de tickets — que le gouverneur de la plateforme a désactivée dans *Administration → Intégrations* ([décision 0040](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0040-integrations-are-switched-on-not-installed.md)). La même requête réussit une fois l'intégration réactivée. | `integration` : sa clé |
| `urn:vectispire:problem:integration-in-use` | Le gouverneur de la plateforme a demandé de désactiver une intégration qu'une configuration utilise encore — le transport SIEM par lequel l'export activé envoie. Rien n'est changé ni enregistré : ce qui attend dans la file n'aurait sinon plus nulle part où aller et serait perdu en silence. Changez d'abord cette configuration — pointez l'export SIEM vers un autre transport, ou désactivez-le — puis désactivez l'intégration. | `integration` : sa clé |

## Un 500 ne s'explique jamais

Un 500 ne porte pas le message de ce qui a échoué. Ce message n'a pas été écrit pour un client — il
peut nommer une table, une colonne, un fichier de l'hôte ou les rouages d'une bibliothèque — il
reste donc dans le journal. Pour enquêter, cherchez le `correlationId` dans le journal du plan de
contrôle :

```text
ERROR … Unexpected failure 6f1c2a9e-… on PATCH /api/v1/users/12
```

## SCIM

`/scim/v2/Users` répond à une valeur refusée, et à un compte protégé, dans le schéma d'erreur de la
[RFC 7644 §3.12](https://www.rfc-editor.org/rfc/rfc7644#section-3.12), parce que c'est ce qu'un
client d'annuaire sait lire. Tout autre refus sur les routes SCIM est un document « problem » comme
ci-dessus.
