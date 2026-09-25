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
   * Si un lead tech ou un développeur met à jour le ticket dans Jira, GitLab, GitHub ou ServiceNow avec une résolution telle que *Faux Positif*, *Won't Fix*, *Refusé* ou *Risque Accepté*, Vectispire intercepte l'événement via un webhook entrant.
   * L'issue dans Vectispire est immédiatement basculée au statut de triage **`not_affected`** avec la justification formelle OpenVEX / CSAF appropriée, et l'événement est tracé dans le **journal d'audit cryptographique** sous l'opération `TICKET_SYNCED`.

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
* **Comportement** : Si la résolution est marquée comme *"Won't Fix"*, *"False Positive"* ou *"Declined"*, le triage de l'issue Vectispire est mis à jour automatiquement.

### 2. 🦊 GitLab Issues
* **URL du Webhook** : `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/gitlab`
* **Événements** : `Issues Events`
* **Comportement** : Lorsque l'issue est fermée ou commentée avec mention *"false positive"* ou *"wontfix"*, le statut Vectispire est synchronisé.

### 3. 🐙 GitHub Issues
* **URL du Webhook** : `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/github`
* **Événements** : `Issues` (action `closed` / `labeled`)

### 4. 🏢 ServiceNow (Table API / Business Rules)
* **URL du Webhook** : `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/servicenow`
* **Événements** : Incident State Change (Close Code: *"Won't Fix"*, *"Solved"*, *"False Positive"*)

---

## 🔒 Sécurité et Chiffrement

* Les jetons d'accès aux trackers (`TICKET_TOKEN`) sont **chiffrés au repos** via AES-GCM-256 avec contexte de clé `setting:ticket_token`.
* Une livraison n'est traitée qu'une fois : son corps est mémorisé trente jours, si bien qu'une requête signée capturée et renvoyée plus tard reçoit *« Delivery already processed »* et ne change rien. La redélivrance du même événement par le traqueur y aboutit aussi.
* Chaque décision de synchronisation produit une entrée horodatée et signée dans le registre d'audit.
