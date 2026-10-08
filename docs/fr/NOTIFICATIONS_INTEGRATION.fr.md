# Guide d'Intégration des Notifications (Discord, Slack, Microsoft Teams)

Vectispire propose un système d'alerte et de notifications en temps réel pour informer immédiatement vos équipes de développement, de sécurité et d'exploitation lors des événements critiques : détection de nouvelles vulnérabilités, régression de Quality Gate, expiration de triage ou achèvement de scan.

---

## 📢 Canaux de Notification Supportés

| Plateforme | Type d'intégration | Format de message | Sécurité & Signature |
|---|---|---|---|
| **Discord** | Webhook natif Discord | Rich Embeds interactifs avec code couleur par sévérité | URL masquée aux non-administrateurs ; non signé |
| **Slack** | Incoming Webhook / App Slack | JSON Block Kit / Message formaté | URL masquée aux non-administrateurs ; non signé — Slack ignorerait une signature |
| **Microsoft Teams** | Power Automate / Workflow Webhook | Adaptive Cards / JSON enrichi | URL masquée aux non-administrateurs ; non signé — Teams ignorerait une signature |
| **Webhooks Génériques** | Endpoint HTTP POST personnalisé | JSON standardisé avec delta de scan | En-têtes `X-Vectispire-Signature` + `X-Vectispire-Timestamp`, quand un secret de signature est posé |

---

## 1. 🟣 Intégration Discord

Vectispire intègre un canal dédié (`DiscordNotificationChannel`) qui formate automatiquement les alertes en **Rich Embeds** avec :
* Un indicateur de couleur dynamique :
  * 🔴 **Rouge** (`#DC2626`) : Vulnérabilités **Critical**
  * 🟠 **Orange** (`#EA580C`) : Vulnérabilités **High**
  * 🟡 **Jaune** (`#D97706`) : Vulnérabilités **Medium**
  * 🟢 **Vert** (`#16A34A`) : Scan propre / Résolution de vulnérabilités
* Champs détaillés : Dépôt / Conteneur ciblé, delta de nouvelles vulnérabilités (+N), vulnérabilités résolues (-N), lien direct vers la console.

### Configuration Discord :
1. Dans votre serveur Discord, accédez aux paramètres du salon textuel souhaité > **Intégrations** > **Webhooks**.
2. Cliquez sur **Nouveau Webhook**, donnez-lui le nom `Vectispire Bot`, et copiez l'URL du webhook (ex: `https://discord.com/api/webhooks/123456789/abcdef...`).
3. Dans Vectispire, rendez-vous dans **Paramètres > Notifications**.
4. Renseignez l'URL dans le champ **URL de Webhook Discord** (`notification_discord_url`) et enregistrez.
5. Vous pouvez déclencher un test d'envoi immédiat depuis la page **Centre de Notifications**.

---

## 2. 🟢 Intégration Slack

### Configuration Slack :
1. Créez une application Slack ou activez les **Incoming Webhooks** sur votre espace de travail :
   * Rendez-vous sur [api.slack.com/apps](https://api.slack.com/apps).
   * Activez *Incoming Webhooks* et cliquez sur **Add New Webhook to Workspace**.
   * Sélectionnez le canal (ex: `#secops-alerts` ou `#dev-security`).
   * Copiez l'URL générée (`https://hooks.slack.com/services/T.../B.../...`).
2. Dans Vectispire (**Paramètres > Notifications**) :
   * Collez l'URL dans le champ **Slack webhook URL** (`notification_slack_url`), qui publie des cartes Block Kit. Le **Webhook URL** générique (`notification_webhook_url`) publie le JSON propre à Vectispire, que Slack n'affiche pas comme une carte.
   * Aucun secret de signature ne s'applique : Slack accepte tout ce qui atteint un incoming webhook et ne vérifie rien, l'URL elle-même est donc l'identifiant — tenez-la hors des tickets et des captures d'écran.

---

## 3. 🔵 Intégration Microsoft Teams

Microsoft Teams prend en charge les alertes Vectispire via les connecteurs de flux de travail **Power Automate** :

### Configuration Teams :
1. Dans Microsoft Teams, rendez-vous dans le canal dédié > **Applications** > **Workflows**.
2. Recherchez et activez le modèle **"Publier sur un canal lorsqu'une requête webhook est reçue"** (*Post to a channel when a webhook request is received*).
3. Copiez l'URL HTTP POST fournie par Power Automate.
4. Dans Vectispire (**Paramètres > Notifications**) :
   * Renseignez cette URL dans le champ **Microsoft Teams webhook URL** (`notification_teams_url`), qui publie une Adaptive Card : rien n'est à mapper dans le concepteur. **Enable Microsoft Teams notifications** (`notification_teams_enabled`) est l'interrupteur à côté.
   * Les messages vers Teams ne sont pas signés, et un workflow déclenché par une requête webhook ne vérifie aucune signature : l'URL du workflow est l'identifiant.

---

## 🔒 Sécurité des Webhooks & Anti-SSRF

* **Protection SSRF stricte (`OutboundUrlGuard`)** : Les destinations pointant vers des adresses privées/internes (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`) sont bloquées par défaut, sauf si le paramètre `notification_allow_private_url` est explicitement activé par un administrateur.
* **Ce qui est chiffré, et ce qui ne l'est pas** : le **secret de signature** (`notification_webhook_secret`) est un identifiant — chiffré au repos en AES-256-GCM, écrit seulement par sa propre route, renvoyé par aucune. Les **URL de webhook** (générique, Slack, Teams, Discord) sont une capacité plutôt qu'un identifiant : elles sont stockées telles qu'écrites et masquées aux non-administrateurs (`Sensitivity.SECRET`), pas chiffrées — et l'URL de webhook propre à une équipe est une simple colonne de `t_team_webhook`. Qui peut lire la base peut les lire.
* **L'export SIEM suit la même règle, pour chaque protocole.** Son point de collecte — une URL pour le webhook, `hôte:port` pour syslog en UDP, TCP ou TLS — est refusé sur une adresse privée tant que `siem_allow_private_destination` n'est pas activé — le paramètre propre à l'export, que seul un administrateur peut changer — et un hôte syslog passe par le même classificateur d'adresses qu'une URL. Un collecteur SIEM sur un réseau interne a besoin de ce paramètre ; le test de connexion répond une issue (délivré, refusé par la politique, non délivré) et laisse l'erreur de la socket au journal du serveur. Son en-tête d'autorisation n'est envoyé qu'avec le webhook, chiffré au repos comme les autres identifiants, et laisser le champ vide à l'enregistrement conserve celui qui est stocké. Les événements partent par la même outbox que les notifications, après la validation du changement qui les a causés — voir la page [Export SIEM](../../docs-site/integrations/siem.fr.md) et la [décision 0025](../architecture/fr/decisions/0025-siem-events-leave-through-the-outbox.md).
* **Signature cryptographique, et rejeu — à la charge du récepteur** : la signature couvre `X-Vectispire-Timestamp` avec le corps exact, si bien que l'horodatage ne peut pas être réécrit et que le récepteur peut certifier l'expéditeur. Un rejeu n'est arrêté que par un récepteur qui vérifie la signature, refuse un horodatage hors d'une fenêtre qu'il choisit, et déduplique sur le `message_id` du message dans cette fenêtre. Un récepteur qui ne fait rien de cela — Slack, Teams, Discord — n'est protégé par aucun des deux en-têtes.
