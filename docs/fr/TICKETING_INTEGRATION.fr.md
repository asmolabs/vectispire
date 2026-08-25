# Guide d'Intégration du Ticketing Bidirectionnel (Jira, GitLab, GitHub, ServiceNow)

Vectispire propose un moteur de synchronisation bidirectionnelle transparent entre son backlog de sécurité ASPM et les outils de gestion de projet des équipes de développement et opérations (Jira, GitLab Issues, GitHub Issues, ServiceNow).

---

## 🎯 Fonctionnalités Clés

1. **Création Automatique de Tickets** :
   * Lors de la découverte d'une vulnérabilité critique ou bloquante (selon la politique de Quality Gate), Vectispire ouvre automatiquement un ticket avec la description exhaustive, le score CVSS/EPSS, le lien vers la preuve et le chemin du fichier affecté.
   * La référence et l'URL du ticket sont liées de manière permanente à l'issue dans Vectispire (`ticketRef`, `ticketUrl`).

2. **Fermeture Automatique lors de la Résolution** :
   * Dès qu'une nouvelle analyse de sécurité confirme que la vulnérabilité n'est plus présente (passage de l'issue à l'état `RESOLVED`), Vectispire appelle l'API du gestionnaire de tickets pour fermer automatiquement le ticket associé avec le commentaire : *"✅ Issue resolved by Vectispire security scan"*.

3. **Synchronisation du Statut & Décisions de Triage (Webhooks Entrants)** :
   * Si un lead tech ou un développeur met à jour le ticket dans Jira, GitLab, GitHub ou ServiceNow avec une résolution telle que *Faux Positif*, *Won't Fix*, *Refusé* ou *Risque Accepté*, Vectispire intercepte l'événement via un webhook entrant.
   * L'issue dans Vectispire est immédiatement basculée au statut de triage **`not_affected`** avec la justification formelle OpenVEX / CSAF appropriée, et l'événement est tracé dans le **journal d'audit cryptographique** sous l'opération `TICKET_SYNCED`.

---

## 🛠️ Configuration des Webhooks Entrants

Dans les paramètres de votre gestionnaire de tickets, ajoutez un Webhook pointant vers votre instance Vectispire :

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
* L'accès au point d'entrée de webhook est isolé et idempotent.
* Chaque décision de synchronisation produit une entrée horodatée et signée dans le registre d'audit.
