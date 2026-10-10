# Guide d'Intégration du Ticketing Bidirectionnel (Jira, GitLab, GitHub, ServiceNow)

Vectispire propose un moteur de synchronisation bidirectionnelle transparent entre son backlog de sécurité ASPM et les outils de gestion de projet des équipes de développement et opérations (Jira, GitLab Issues, GitHub Issues, ServiceNow).

---

## 🎯 Fonctionnalités Clés

1. **Création Automatique de Tickets** :
   * Lors de la découverte d'une vulnérabilité critique ou bloquante (selon la politique de Quality Gate), Vectispire ouvre automatiquement un ticket avec la description exhaustive, le score CVSS/EPSS, le lien vers la preuve et le chemin du fichier affecté.
   * La référence et l'URL du ticket sont liées de manière permanente à l'issue dans Vectispire (`ticketRef`, `ticketUrl`).

2. **Fermeture Automatique lors de la Résolution** :
   * Dès qu'une nouvelle analyse de sécurité confirme que la vulnérabilité n'est plus présente (passage de l'issue à l'état `RESOLVED`), Vectispire appelle l'API du gestionnaire de tickets pour fermer automatiquement le ticket associé avec le commentaire : *"✅ Issue resolved by Vectispire security scan"*.
   * **Seul un ticket ouvert par Vectispire est fermé ainsi.** Une référence rattachée à la main désigne un ticket qui peut appartenir à quelqu'un d'autre : c'est à cette personne de le fermer. Et une référence n'est acceptée que sous la forme du traqueur configuré — `#123` pour GitLab et GitHub, `CLÉ-123` dans le projet configuré pour Jira, un sys_id ou un numéro d'incident pour ServiceNow — parce qu'elle entre dans une URL envoyée avec le jeton de l'intégration.
   * **ServiceNow est fermé par `sys_id`.** La référence gardée est le numéro d'incident que les gens lisent (`INC0012345`), mais la Table API ne désigne un enregistrement que par son `sys_id` : Vectispire interroge donc d'abord `/api/now/table/incident?sysparm_query=number=…&sysparm_fields=sys_id`, puis envoie un `PATCH` sur cet enregistrement — le compte a besoin du droit de lecture sur `incident` en plus de l'écriture. Une référence qui est déjà un `sys_id` est utilisée telle quelle. Les issues GitLab sont fermées par `PUT`, celles de GitHub par `PATCH` ; jusqu'à cette correction chaque fermeture partait en `POST`, que ni GitLab ni ServiceNow ne routent, et échouait.

3. **Synchronisation du Statut & Décisions de Triage (Webhooks Entrants)** :
   * Si un lead tech ou un développeur ferme le ticket dans Jira, GitLab, GitHub ou ServiceNow avec une résolution que Vectispire sait lire, Vectispire intercepte l'événement via un webhook entrant et le lit comme l'une de deux affirmations différentes :
     * **Un refus** — *Won't Fix*, *Declined*, *Rejected*, *Risk Accepted*, *Withdrawn*, ou le `not_planned` de GitHub — dit que l'équipe ne corrigera pas. Il est proposé comme **`will_not_fix`** (*Ne sera pas corrigé — risque accepté*), **sans** justification VEX et avec une date de réexamen proposée à quatre-vingt-dix jours ; la personne qui l'accorde pose la sienne. Un refus ne dit rien de l'exposition du produit : il ne devient donc jamais `not_affected`. Jusqu'à la 0.11.0, il le devenait, avec la justification `inline_mitigations_already_exist` — une atténuation que personne n'avait construite, et que les documents signés auraient portée une fois la demande approuvée ([décision 0041](../architecture/fr/decisions/0041-will-not-fix-is-not-not-affected.md)).
     * **Un faux positif explicite** — *False Positive*, *Cannot Reproduce*, *Not an Issue*, ou les mots « false positive » dans une issue GitHub ou GitLab — est une affirmation sur l'exposition, et lui seul est proposé comme **`not_affected`**, avec la justification `vulnerable_code_not_in_execute_path`.
   * Dans les deux cas, la décision est **mise en file pour approbation par une seconde personne**, pas appliquée : l'issue passe en `pending_approval`, et les documents exportés la montrent en cours d'investigation jusqu'à ce que quelqu'un l'approuve. Un gestionnaire de tickets n'est pas une personne, ni authentifié comme telle, et ce qui est accordé part tel quel dans les documents CycloneDX, OpenVEX et CSAF signés. L'événement est tracé dans le journal d'audit chaîné par empreintes sous l'opération `TICKET_SYNCED`.
   * **Une décision qu'une personne a réglée ne bouge pas sur un ticket.** Sur une issue déjà `not_affected`, `will_not_fix` ou `fixed`, la parole du traqueur est inscrite au journal d'audit et rien ne change. Quand elle contredit le statut réglé — un *Won't Fix* sur une issue déclarée non affectée, par exemple —, l'entrée est `TRIAGE_CONTRADICTED_BY_TRACKER`, signalée au SIEM comme `VECTI-SEC-037` : l'un des deux se trompe, et seule une personne peut dire lequel.

---

## 🛠️ Configuration des Webhooks Entrants

Dans les paramètres de votre gestionnaire de tickets, ajoutez un Webhook pointant vers votre instance Vectispire :

> **Réglez d'abord le secret du webhook** (**Paramètres → Tickets → secret du webhook entrant**), et
> la même valeur dans le traqueur. La route ne peut pas porter de session : le secret est toute son
> authentification, et **sans lui elle refuse chaque appel** avec `403` et *« The ticket webhook is
> not configured on this instance »*, ce que montre le journal de livraison du traqueur. Un secret
> enregistré qu'aucune clé configurée ne déchiffre — `ENCRYPTION_KEY` perdue, ou ancienne clé retirée
> de `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` — refuse avec `401`, et l'écran des paramètres le montre
> comme non configuré : réglez-le de nouveau. Comment chaque traqueur le présente : GitLab dans
> `X-Gitlab-Token`, GitHub comme HMAC du corps dans `X-Hub-Signature-256`, Jira et ServiceNow dans
> `X-Vectispire-Token`.

### 1. 🏷️ Jira Software (Atlassian)
* **URL du Webhook** : `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/jira`
* **Événements** : `Issue -> updated`
* **Comportement** : Une résolution *"Won't Fix"*, *"Declined"* ou *"Rejected"* met en file une demande `will_not_fix` pour approbation ; *"False Positive"* ou *"Cannot Reproduce"*, une demande `not_affected`.

### 2. 🦊 GitLab Issues
* **URL du Webhook** : `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/gitlab`
* **Événements** : `Issues Events`
* **Comportement** : Une issue dont le titre ou la description dit *« false positive »* met en file une demande `not_affected` pour approbation ; une issue fermée avec *« wontfix »* ou *« won't fix »* dans son titre, une demande `will_not_fix`.

### 3. 🐙 GitHub Issues
* **URL du Webhook** : `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/github`
* **Événements** : `Issues` (action `closed` / `labeled`)
* **Comportement** : Une issue fermée comme *not planned* (`state_reason: not_planned`) met en file une demande `will_not_fix` pour approbation — c'est la seule façon qu'a GitHub de fermer sans avoir terminé, et elle ne dit rien de l'atteignabilité. Seuls les mots *« false positive »* dans le corps de l'issue mettent en file une demande `not_affected`.

### 4. 🏢 ServiceNow (Table API / Business Rules)
* **URL du Webhook** : `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/servicenow`
* **Événements** : Incident State Change (Close Code: *"Won't Fix"*, *"Solved"*, *"False Positive"*)
* **Comportement** : Un code de clôture *"Won't Fix"*, *"Risk Accepted"* ou *"Withdrawn"* met en file une demande `will_not_fix` pour approbation ; *"False Positive"* ou *"Not an Issue"*, une demande `not_affected`.

---

## 🔒 Sécurité et Chiffrement

* Les jetons d'accès aux trackers (`TICKET_TOKEN`) sont **chiffrés au repos** via AES-GCM-256 avec contexte de clé `setting:ticket_token`.
* Une livraison n'est traitée qu'une fois : son corps est mémorisé trente jours, si bien qu'une requête signée capturée et renvoyée plus tard reçoit *« Delivery already processed »* et ne change rien. La redélivrance du même événement par le traqueur y aboutit aussi.
* Chaque décision de synchronisation produit une entrée horodatée dans le journal d'audit chaîné par empreintes.
