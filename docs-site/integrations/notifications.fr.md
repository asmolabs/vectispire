# Notifications

Trois destinations se déclenchent quand un scan fait **apparaître ou réapparaître** quelque
chose — pas à chaque scan, ce qui est ce qui garde le canal lisible.

| Destination | |
|---|---|
| **Webhook** | votre propre point d'entrée, un bus — les événements de sécurité pour un SOC ont leur propre [export SIEM](siem.md) |
| **Microsoft Teams** | une carte adaptative via un workflow Power Automate |
| **Courriel** | une liste de diffusion |

Elles sont **indépendantes, pas exclusives**. Une équipe veut généralement la carte dans son
canal *et* le courriel sur une liste de diffusion : chaque destination reçoit donc sa propre
ligne de file d'envoi, si bien qu'un serveur de messagerie en panne ne fait pas recevoir deux
fois le message à Teams lors de la reprise.

## Une remise sur laquelle compter

Le message est écrit dans une **file d'envoi, dans la même transaction que les résultats du
scan**, et remis par le planificateur avec une temporisation exponentielle plafonnée.

C'est la différence entre une notification et un espoir. Un plantage entre l'enregistrement et
le POST perdait autrefois le message en silence ; un point d'entrée brièvement injoignable
était journalisé une fois puis oublié. Désormais, l'écriture et l'intention d'envoyer sont
validées ensemble, ou aucune des deux ne l'est.

## Webhooks signés

Les messages de webhook peuvent être signés : **HMAC-SHA256 sur l'horodatage et le corps
exact**, dans l'en-tête `X-Vectispire-Signature`.

Vérifiez-la si vous le pouvez. C'est ce qui permet à un destinataire de distinguer un message
envoyé par Vectispire d'un message envoyé par quiconque a appris l'URL — cela vaut la peine
pour un script, un bus ou votre propre passerelle. Slack et Teams acceptent ce qui arrive et ne
peuvent rien vérifier : la signature n'y achète rien.

L'horodatage est à l'intérieur de la signature, il ne peut donc pas être réécrit — mais un rejeu
n'est refusé que par un destinataire qui vérifie : rejetez un horodatage hors d'une fenêtre que
vous choisissez, et dédupliquez sur le `message_id` du message dans cette fenêtre.

Un secret vide signifie non signé, et c'est ce que reste un déploiement existant tant que vous
n'en posez pas un.

## Microsoft Teams

Teams est atteint par un **workflow** Power Automate. Le connecteur Office 365 qu'il remplace a
été retiré.

Vectispire publie une carte adaptative : rien n'a donc à être cartographié dans le concepteur —
créez le workflow, prenez son URL, collez-la.

## Quand un jeton d'intégration change d'état {#integration-token-alerts}

Depuis la 0.11.1, les mêmes canaux sont prévenus quand le [jeton du tracker](ticketing.md#token-expiry) ou
le [jeton d'une connexion de forge](../administration/forge-connections.md#token-expiry) **change
d'état** : quatorze jours avant son expiration, quand il a expiré ou que le serveur l'a refusé, et quand
il fonctionne de nouveau ou n'est plus sur le point d'expirer. Une fois par changement, jamais une fois
par heure ; un redémarrage ne redit rien.

- **Les canaux de l'installation** : le webhook global, Slack, Teams, Discord et le courriel — chacun
  configuré, une ligne de file d'envoi chacun, comme pour un delta de scan. Le webhook propre d'une
  équipe n'est pas prévenu : le jeton est celui de l'installation. Le seuil des issues ne s'applique pas ;
  il porte sur les constats.
- **Les mêmes règles** : l'URL lue à l'envoi, l'interrupteur des adresses privées, la signature du
  webhook.
- **Ce qu'il dit** : le tracker ou la connexion par son nom, le serveur et son adresse, la date ou le
  statut et depuis quand, et un lien vers l'écran où remplacer le jeton quand le déploiement connaît son
  adresse publique. **Jamais le jeton**, ni un en-tête.
- **Le corps du webhook** se distingue d'un delta de scan par `event: "token_state_changed"`, avec
  `credential` (`tracker_token` ou `forge_connection`), `name`, `reference`, `state` et
  `previous_state` (`none`, `expires_soon`, `expired`, `refused`), `signature_id` (l'[événement
  SIEM](siem.md#catalogue-des-evenements), `VECTI-SEC-038` à `040`), `expires_at`, `refused_status`,
  `refused_since`, `observed_at` et `message_id`.

Le même changement est dans le journal d'audit et envoyé au SIEM — voir les tableaux des pages
[tickets](ticketing.md#token-expiry) et [connexions de forge](../administration/forge-connections.md#token-expiry).

## Le rapport de posture hebdomadaire {#the-weekly-posture-report}

Désactivé par défaut, et il existe pour couvrir l'angle mort que toutes les autres
notifications partagent.

Tout ce qui précède se déclenche quand quelque chose *apparaît*. C'est juste pour une alerte et
faux pour un rapport : une semaine calme, personne n'est prévenu de rien — et une semaine calme
est aussi celle où une cible n'a silencieusement pas été analysée depuis vingt jours.

Une fois par semaine, vers le webhook et les destinataires courriel : combien il y en a, dans
quel sens cela bouge, et ce qui n'a jamais été examiné.

Il n'a pas besoin de file d'envoi, contrairement à un delta de scan. Un rapport se dérive de la
base de données, donc un envoi échoué est simplement recalculé au tour suivant.

## Configurer

**Notifications**, par destination : l'URL ou les destinataires, le secret le cas échéant, et
les événements auxquels s'abonner.
