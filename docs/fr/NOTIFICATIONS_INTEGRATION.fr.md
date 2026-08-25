# Guide d'Intégration des Notifications (Discord, Slack, Microsoft Teams)

Vectispire propose un système d'alerte et de notifications en temps réel pour informer immédiatement vos équipes de développement, de sécurité et d'exploitation lors des événements critiques : détection de nouvelles vulnérabilités, régression de Quality Gate, expiration de triage ou achèvement de scan.

---

## 📢 Canaux de Notification Supportés

| Plateforme | Type d'intégration | Format de message | Sécurité & Signature |
|---|---|---|---|
| **Discord** | Webhook natif Discord | Rich Embeds interactifs avec code couleur par sévérité | URL de Webhook chiffrée |
| **Slack** | Incoming Webhook / App Slack | JSON Block Kit / Message formaté | Signature HMAC-SHA256 supportée |
| **Microsoft Teams** | Power Automate / Workflow Webhook | Adaptive Cards / JSON enrichi | Signature HMAC-SHA256 supportée |
| **Webhooks Génériques** | Endpoint HTTP POST personnalisé | JSON standardisé avec delta de scan | En-têtes `X-Vectispire-Signature` + `X-Vectispire-Timestamp` |

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
   * Collez l'URL dans le champ **URL du Webhook de notification** (`notification_webhook_url`).
   * *(Optionnel)* Définissez un **Secret de Webhook** (`notification_webhook_secret`) pour que Vectispire signe chaque payload avec HMAC-SHA256.

---

## 3. 🔵 Intégration Microsoft Teams

Microsoft Teams prend en charge les alertes Vectispire via les connecteurs de flux de travail **Power Automate** :

### Configuration Teams :
1. Dans Microsoft Teams, rendez-vous dans le canal dédié > **Applications** > **Workflows**.
2. Recherchez et activez le modèle **"Publier sur un canal lorsqu'une requête webhook est reçue"** (*Post to a channel when a webhook request is received*).
3. Copiez l'URL HTTP POST fournie par Power Automate.
4. Dans Vectispire (**Paramètres > Notifications**) :
   * Renseignez cette URL dans le champ **URL du Webhook de notification** (`notification_webhook_url`).
   * Si vous activez la signature, ajoutez une étape de vérification d'en-tête HMAC dans votre workflow Power Automate.

---

## 🔒 Sécurité des Webhooks & Anti-SSRF

* **Protection SSRF stricte (`OutboundUrlGuard`)** : Les destinations pointant vers des adresses privées/internes (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`) sont bloquées par défaut, sauf si le paramètre `notification_allow_private_url` est explicitement activé par un administrateur.
* **Chiffrement au repos** : Les secrets et jetons de webhooks sont stockés chiffrés avec AES-GCM-256.
* **Signature cryptographique** : Les en-têtes `X-Vectispire-Signature` et `X-Vectispire-Timestamp` préviennent les attaques par rejeu et permettent au récepteur de certifier l'authenticité de l'expéditeur.
