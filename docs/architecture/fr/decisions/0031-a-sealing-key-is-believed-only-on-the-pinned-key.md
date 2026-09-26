# 0031 — La clé de scellement d'un agent n'est crue que sur la parole de sa clé de signature épinglée

**Date :** 2026-09-26 · **Statut :** acceptée · **Amende :** [0003](0003-long-polling-for-agents.md) · **Décideur :** Laurent Boucher

## Contexte

Un agent en mode `delegated` reçoit avec chaque tâche la clé SSH ou le jeton HTTPS d'un dépôt,
scellé ([`SealedEnvelope`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/crypto/SealedEnvelope.java) :
X25519, HKDF, AES-256-GCM) pour une clé publique que l'agent fabrique à chaque démarrage. Le but est
écrit dans cette classe : la plupart des déploiements placent un reverse proxy devant le plan de
contrôle, TLS s'y termine, et le scellement est ce qui tient l'identifiant hors de portée de qui
administre ce proxy.

Ce but ne tenait que si la clé pour laquelle le plan de contrôle scellait était bien celle de
l'agent. Elle était prise dans le `hello` de l'agent, non signée, sur le canal même dont le
scellement se méfie, et écrasée par chaque `hello` suivant — y compris un `hello` vide, après quoi
le plan de contrôle se rabattait sur l'envoi de l'identifiant en clair sous TLS. Une partie capable
de réécrire le canal pouvait donc choisir la clé ou la retirer. L'audit de sécurité du 2026-09-26 l'a
consigné comme son dernier constat ouvert.

L'agent détient déjà une clé que le plan de contrôle n'a **pas** apprise par le protocole agent :
la clé Ed25519 de signature des résultats qu'un administrateur épingle sur la ligne de l'agent
([`ResultAttestation`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/crypto/ResultAttestation.java)).
Sa moitié privée est dans la configuration de l'agent, sa moitié publique est arrivée par la session
d'un administrateur.

## Décision

**Le scellement sort un proxy qui termine TLS de la frontière de confiance, pourvu qu'une clé de
signature soit épinglée.** Concrètement :

1. **L'agent signe sa clé de scellement avec sa clé de signature épinglée**
   ([`SealingKeyAttestation`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/crypto/SealingKeyAttestation.java)).
   La signature est Ed25519 sur
   `sha256("vectispire:agent-sealing-key:v1" ‖ 0x00 ‖ agentId ‖ 0x00 ‖ génération ‖ 0x00 ‖ sha256(clé))` :
   - une chaîne de contexte propre, distincte du `vectispire:agent-result:v1` des résultats, de sorte
     qu'une signature faite pour un usage ne se vérifie jamais pour l'autre bien qu'une seule clé
     fasse les deux ;
   - l'identifiant de l'agent (UUID canonique), pour qu'une annonce ne puisse pas être rejouée sur un
     autre agent qu'un opérateur aurait configuré avec la même clé de signature ;
   - la **génération** — le moment où la paire a été fabriquée, en millisecondes depuis l'époque —
     pour que le plan de contrôle garde la plus récente et refuse une annonce plus ancienne renvoyée ;
   - les octets SPKI décodés de la clé, qui sont ce pour quoi l'enveloppe est scellée.
2. **L'annonce a sa propre route**, `POST /api/v1/agent/sealing-key` (`public_key`, `generation`,
   `signature`), appelée après le `hello` parce que l'agent apprend son identifiant dans la réponse
   du `hello`. Elle répond 204 quand la clé est acceptée, 412 quand aucune clé de signature n'est
   épinglée, 403 quand la signature ne se vérifie pas, 409 quand la génération n'est pas plus récente
   que celle de la clé détenue. Le 403 et le 409 sont audités (`AGENT_SEALING_KEY_REFUSED`) et
   émettent l'événement SIEM `ZAN-SEC-020` ; un changement accepté est audité
   (`AGENT_SEALING_KEY_ACCEPTED`).
3. **Persistante.** Le `hello` n'écrit plus la clé de scellement ; son `sealing_public_key` non signé
   n'est lu par rien. La clé acceptée ne change que par une annonce correctement signée et plus
   récente, écrite par une seule instruction conditionnelle, et l'entité ne peut pas écrire la colonne
   quand la ligne est enregistrée pour une autre raison. Un `hello` sans clé, ou avec une clé non
   signée quelle qu'elle soit, la laisse en place.
4. **Jamais de remise en clair.** Un identifiant délégué part scellé pour la clé vérifiée, ou la
   prise en charge répond 412 en nommant l'étape à accomplir et l'analyse retourne dans la file. Le
   chiffrement du lien n'est plus consulté : un TLS qu'un proxy termine ne protège rien de ce proxy,
   et, vue du plan de contrôle, une annonce retirée en chemin ressemble exactement à un agent qui n'en
   a jamais fait.
5. **Un agent sans clé de signature épinglée ne reçoit aucun identifiant délégué.** Pas de confiance
   au premier usage : la paire est refaite à chaque démarrage, si bien qu'une clé crue à première vue
   devrait être crue de nouveau, non signée, après chaque redémarrage — ce qui est le constat même.
6. **Le retour arrière appartient à un administrateur.** `DELETE /api/v1/admin/agents/{id}/sealing-key`
   oublie la clé et sa génération (`AGENT_SEALING_KEY_RESET`, SIEM `ZAN-SEC-014`) ; épingler,
   remplacer ou retirer la clé de signature l'oublie aussi, puisque la nouvelle clé ne se porte pas
   garante de ce que l'ancienne a signé. L'agent annonce de nouveau à son prochain démarrage, ou à sa
   prochaine prise en charge dès qu'un identifiant a été retenu après une acceptation.
7. **V40** ajoute `t_agent.sealing_key_generation` et oublie toutes les clés de scellement stockées :
   aucune n'avait été vérifiée.

## Compatibilité

Le contrat agent reste `1`. Sa règle veut que le numéro change quand le comportement d'un agent plus
ancien devient *incorrect* ; ici un agent plus ancien se voit refuser un identifiant explicitement,
et tout le reste de son comportement est inchangé. L'incrémenter refuserait d'emblée le `hello` des
agents plus anciens, les agents `local` compris.

| Agent | Plan de contrôle | Résultat |
|---|---|---|
| cette version, clé de signature épinglée et configurée | cette version | identifiants scellés pour la clé vérifiée |
| cette version, sans clé de signature | cette version | `local` fonctionne ; identifiants délégués retenus (412, journalisé par l'agent) |
| plus ancien | cette version | le `hello` fonctionne, les analyses d'images et `local` aussi ; identifiants délégués retenus avec un 412 que l'agent journalise |
| cette version | plus ancien | le `hello` porte toujours la clé non signée, pour laquelle ce plan de contrôle scelle ; la route signée répond 404, lu comme « non pris en charge » |

## Alternatives envisagées

- **Confiance au premier usage.** Rejetée pour la raison du point 5 : une clé éphémère a un premier
  usage à chaque démarrage.
- **Garder le repli en clair sous TLS pour les agents sans clé.** C'est exactement la dégradation que
  décrit le constat ; l'agent refusait déjà un tel identifiant, mais seulement après que le proxy
  l'avait lu.
- **Signer la clé dans le `hello`.** L'agent ne connaît pas son identifiant avant la réponse du
  `hello`, et signer sans lui perd le lien à un agent.
- **Une clé de scellement durable sur le disque de l'agent, épinglée comme la clé de signature.** Un
  second secret à provisionner, protéger et faire tourner par agent, là où signer la clé éphémère
  avec la clé déjà épinglée ne coûte rien de nouveau.

## Conséquences

- **Un opérateur doit épingler une clé de signature avant de déléguer des identifiants** — l'icône de
  cadenas de l'écran des agents, ou `PUT /api/v1/admin/agents/{id}/signing-key` — et configurer sa
  moitié privée dans `VECTISPIRE_AGENT_SIGNING_KEY`. Cette clé atteste alors aussi les résultats de
  l'agent ; on ne peut pas avoir l'un sans l'autre, et c'est voulu.
- Une mise à niveau arrête les analyses déléguées des agents existants tant que ces deux étapes ne
  sont pas faites et l'agent mis à niveau. Le 412 de la prise en charge et le « identifiants
  retenus » de l'écran le disent ; rien n'est envoyé en clair entre-temps.
- Un hôte dont l'horloge recule produit des clés que le plan de contrôle refuse comme plus
  anciennes ; le remède est l'horloge ou une réinitialisation par un administrateur.
- Ce que cela ne couvre **pas** : qui détient la configuration de l'agent — sa clé de signature —
  peut annoncer une clé à lui ; un hôte d'agent compromis reste hors du périmètre, comme dans 0003.
  Un proxy peut toujours laisser tomber l'annonce ou la prise en charge : c'est un déni de service,
  pas une divulgation de l'identifiant.

## Amende

[0003](0003-long-polling-for-agents.md) disait qu'une clé est scellée « vers la clé publique que
l'agent a annoncée à l'enrôlement ». Elle n'est plus scellée que pour une clé dont la clé de signature
épinglée de l'agent s'est portée garante.
