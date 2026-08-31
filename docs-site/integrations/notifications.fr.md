# Notifications

Trois destinations se déclenchent quand un scan fait **apparaître ou réapparaître** quelque
chose — pas à chaque scan, ce qui est ce qui garde le canal lisible.

| Destination | |
|---|---|
| **Webhook** | votre propre point d'entrée, un bus, un SIEM |
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

Un secret vide signifie non signé, et c'est ce que reste un déploiement existant tant que vous
n'en posez pas un.

## Microsoft Teams

Teams est atteint par un **workflow** Power Automate. Le connecteur Office 365 qu'il remplace a
été retiré.

Vectispire publie une carte adaptative : rien n'a donc à être cartographié dans le concepteur —
créez le workflow, prenez son URL, collez-la.

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
