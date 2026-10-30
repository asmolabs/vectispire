# 0040 — Une intégration s'active, elle ne s'installe pas : les forges, les transports SIEM, les fournisseurs d'IA, les canaux de notification et les trackers que le gouverneur active

**Date :** 2026-10-07 · **Statut :** acceptée · **S'appuie sur :** [0025](0025-siem-events-leave-through-the-outbox.md), [0035](0035-report-plugins.md), [0037](0037-discovering-repositories-at-setup.md) · **Décideur :** Laurent Boucher

*Acceptée le 2026-10-07 par le responsable produit (option A ci-dessous). Construite après la mise en
production de fin octobre ; rien n'en est dans 0.11.0.*

## Contexte

Une installation doit pouvoir choisir avec quels systèmes extérieurs elle parle : GitLab mais pas
GitHub, un SIEM en syslog TLS mais jamais un webhook. Aujourd'hui, chaque adaptateur est ouvert à tous :

- **Forges** (0037) : `ForgeKind` vaut GitHub et GitLab, tous deux proposés dans le formulaire de
  connexion ; Bitbucket Cloud et Data Center sont prévus (D8). Ajouter un dépôt par son URL — « git
  tout court » — n'est pas une connexion forge et n'en demande aucune ; les hôtes clonables sont déjà
  restreints par `VECTISPIRE_GIT_ALLOWED_HOSTS`.
- **SIEM** (0025) : une destination, quatre transports (`SiemProtocol` : webhook, syslog UDP, TCP et
  TLS), en CEF ou JSON.
- **IA** (`AiProvider`) : Ollama, sur un hôte que l'exploitant fait tourner, et OpenAI.
- **Notifications** (`Setting`, section notifications) : un webhook générique, Microsoft Teams, Slack,
  Discord et l'e-mail.
- **Trackers** (`TicketProvider`) : tickets GitLab, GitHub, Jira et ServiceNow.

La demande parlait de « plugins » : choisir dans l'administration ce qui est chargé ou non. Deux choses
peuvent s'entendre.

## Décision

**Option A — des intégrations activées et désactivées, dans le produit.** Les adaptateurs restent dans
Vectispire. Un registre liste chaque intégration — les types de forge, les transports SIEM, les
fournisseurs d'IA, les canaux de notification et les trackers (amendé le 2026-10-07) — et le gouverneur
de la plateforme active ou désactive chacune dans *Administration → Intégrations*. Une installation qui
veut Ollama et jamais OpenAI, Teams et jamais Discord, le dit une fois.

1. **Une intégration désactivée est injoignable, pas seulement masquée.** Elle quitte chaque
   formulaire et chaque liste qui la proposerait ; ses routes refusent par un 409
   `integration-disabled` qui la nomme ; aucun chemin du code ne l'appelle — c'est l'entrée de
   l'adaptateur qui en décide, pas la garde sortante.
2. **Ce qui l'utilise déjà est suspendu, jamais supprimé.** Une connexion forge d'un type désactivé
   garde sa ligne et son jeton chiffré, se lit *suspendue — intégration désactivée*, et ne lance ni
   découverte ni lecture des relectures ; une ligne de checklist qu'elle alimentait n'a pas de données,
   avec cette raison. La réactiver la reprend telle qu'elle était.
3. **Ce qui est désactivé en service dépend de ce qui serait perdu.**
   - **Un transport SIEM ou un canal de notification en service ne peut pas être désactivé.** On change
     d'abord sa configuration : des événements de sécurité ou des alertes restés dans l'outbox sans
     destination seraient perdus en silence, l'échec même que 0025 et 0033 empêchent. Le refus le dit.
   - **Un fournisseur d'IA en service peut l'être**, et les fonctions qui le lisent disent *IA
     indisponible — fournisseur désactivé* plutôt que de répondre par un autre fournisseur : rien
     d'enregistré n'est perdu, et une revue ne passe jamais en silence d'un hôte de l'exploitant à un
     service hébergé.
   - **Un tracker en service est suspendu comme une connexion forge** : les liens entre issues et
     tickets sont gardés, aucun ticket n'est ouvert ni synchronisé, et la réactivation reprend.
4. **Chaque bascule est un geste de gouvernance.** Auditée, et envoyée au SIEM comme changement de
   réglage de sécurité. Activer élargit ce que l'installation peut joindre et peut passer sous les
   quatre yeux par le même réglage que l'enregistrement des plugins ; désactiver le restreint et ne
   demande personne d'autre.
5. **Les valeurs par défaut ne changent rien.** Une mise à niveau et une nouvelle installation
   commencent avec chaque intégration existante activée ; une installation restreint à partir de là.
   Un nouvel adaptateur (Bitbucket, D8) arrive désactivé : une mise à niveau n'élargit jamais la
   portée d'une installation sans un geste.

## Alternatives écartées

- **Option B — des modules chargés à part** (un jar par adaptateur, présent ou absent). Écartée. Un
  module chargé dans le plan de contrôle tourne avec ses secrets — `ENCRYPTION_KEY`, la base — et
  chacun demanderait ce qu'ont les plugins de scan et de rapport (un artefact signé, un signataire
  vérifié, un registre sous quatre yeux) sans l'isolation qui les rend sûrs : eux tournent dans un
  conteneur qui ne joint rien, un adaptateur de forge ou de SIEM doit porter des jetons et joindre le
  réseau interne. Le coût d'un système de plugins pour un gain qu'un interrupteur donne.
- **Une liste fixée au déploiement** (une variable d'environnement des types activés). Écartée comme
  seul moyen : invisible à l'écran, non auditée, changée par qui modifie le déploiement. Elle peut
  rester comme borne supérieure posée par l'exploitant — ce que le gouverneur peut activer — si une
  installation la demande.

## Conséquences

- Le formulaire de connexion, les réglages SIEM et les écrans de découverte lisent le registre ; la
  référence de l'API nomme `integration-disabled`.
- Chaque adaptateur ajouté ensuite — Bitbucket d'abord — s'inscrit au registre et arrive désactivé.
- Une connexion suspendue se voit comme telle, en anglais et en français, avec ce que la réactivation
  fait.

## Mise en œuvre, en lots (après la mise en production)

| Lot | Contenu | Taille |
|---|---|---|
| I1 | Le registre dans une table à lui (`t_integration`, pas un réglage : un réglage ne garde ni qui l'a basculé ni quand), la route du gouverneur et l'audit ; 409 sur les routes d'une intégration désactivée | M |
| I2 | Connexions forge : l'état suspendu, découverte et lecture des relectures sautées avec leur raison | M |
| I3 | SIEM : les transports dans le registre, le refus d'un transport en service | S |
| I4 | L'écran *Administration → Intégrations*, les formulaires filtrés ; la documentation en anglais et en français | M |
| I5 | Fournisseurs d'IA : le registre, *IA indisponible — fournisseur désactivé* dans les fonctions qui le lisent — **construit pour la 1.0.0-rc.1** | S |
| I6 | Canaux de notification (le refus en service) et trackers (suspendus) — **les deux moitiés construites pour la 1.0.0-rc.1** | M |

**Tant que le lot d'une famille n'était pas construit, sa désactivation était refusée** (amendé pour la
1.0.0-rc.1, et clos dans celle-ci). I1 listait toutes les familles : un gouverneur pouvait donc désactiver
un fournisseur d'IA ou un canal de notification qu'aucun adaptateur ne vérifiait — enregistré et
journalisé, cela n'arrêtait rien, contre le §1. Le registre refusait `enabled: false` pour ces familles —
409 `integration-not-switchable` — jusqu'à ce qu'I5 et la moitié notifications d'I6 fassent consulter le
registre par chacune de leurs entrées. Les deux sont construits dans la même version : toute famille peut
désormais être désactivée, et le refus, sa cause et `IntegrationFamily.suspendable` disparaissent — aucune
version ne les a livrés. Une famille ajoutée plus tard est branchée dans le changement qui la liste.

**Comment I5 et I6 tiennent le §1 et le §3** (1.0.0-rc.1) :

- **IA.** Chaque appel à un modèle sort par une méthode d'`AiReviewService`, qui demande au registre le
  fournisseur qu'elle a lu une fois et auquel elle se tient — son URL, sa clé, sa requête — : un
  fournisseur désactivé est refusé, jamais remplacé par l'autre. Les fonctions qui le lisent — le rapport
  OWASP depuis le bouton ou après un scan, l'explication du conseiller, le test du point d'accès — refusent
  avant d'enregistrer quoi que ce soit, par un 409 `integration-disabled` ouvert par *AI unavailable —
  provider disabled* ; le statut du conseiller indique `providerEnabled: false` et n'interroge rien. Choisir
  un fournisseur désactivé, ou activer la revue sur l'un d'eux, est refusé comme le choix d'un tracker :
  vérifié, pas retenu — rien n'est perdu si une bascule tombe entre la vérification et l'écriture.
- **Notifications.** Un canal est en service quand il a où envoyer : son URL (Teams avec son interrupteur
  activé), ses destinataires ou les rappels des checklists (le courriel), le webhook propre d'une équipe (le
  webhook générique). La réponse et les réglages qui configurent un canal sont une seule lecture
  (`NotificationDestinations`), pour que le refus ne puisse pas manquer une destination que
  l'enregistrement connaît. Un enregistrement qui configure un canal retient sa ligne `for share` dans la
  transaction qui l'écrit — l'enregistrement des réglages est devenu une transaction pour cela, et le
  webhook d'une équipe une autre — comme le fait l'export SIEM : une bascule attend l'enregistrement et le
  lit en service, un enregistrement après la bascule le lit désactivé. Chaque canal consulte le registre à
  sa propre entrée, pas au relais, car le rapport hebdomadaire, les rappels, les alertes de jeton et le
  bouton de test atteignent les canaux sans lui ; une ligne en file pour un canal désactivé à la main est
  retenue, sans tentative comptée, jamais envoyée ni abandonnée.
