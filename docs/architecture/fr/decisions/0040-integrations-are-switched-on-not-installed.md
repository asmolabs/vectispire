# 0040 — Une intégration s'active, elle ne s'installe pas : les forges et les transports SIEM que le gouverneur active

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

La demande parlait de « plugins » : choisir dans l'administration ce qui est chargé ou non. Deux choses
peuvent s'entendre.

## Décision

**Option A — des intégrations activées et désactivées, dans le produit.** Les adaptateurs restent dans
Vectispire. Un registre liste chaque intégration — les types de forge, les transports SIEM — et le
gouverneur de la plateforme active ou désactive chacune dans *Administration → Intégrations*.

1. **Une intégration désactivée est injoignable, pas seulement masquée.** Elle quitte chaque
   formulaire et chaque liste qui la proposerait ; ses routes refusent par un 409
   `integration-disabled` qui la nomme ; aucun chemin du code ne l'appelle — c'est l'entrée de
   l'adaptateur qui en décide, pas la garde sortante.
2. **Ce qui l'utilise déjà est suspendu, jamais supprimé.** Une connexion forge d'un type désactivé
   garde sa ligne et son jeton chiffré, se lit *suspendue — intégration désactivée*, et ne lance ni
   découverte ni lecture des relectures ; une ligne de checklist qu'elle alimentait n'a pas de données,
   avec cette raison. La réactiver la reprend telle qu'elle était.
3. **Un transport SIEM en service ne peut pas être désactivé.** On change d'abord la configuration du
   SIEM : des événements de sécurité restés dans l'outbox sans destination seraient perdus en silence,
   l'échec même que 0025 empêche. Le refus le dit.
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
| I1 | Le registre, son réglage, la route du gouverneur et l'audit ; 409 sur les routes d'une intégration désactivée | M |
| I2 | Connexions forge : l'état suspendu, découverte et lecture des relectures sautées avec leur raison | M |
| I3 | SIEM : les transports dans le registre, le refus d'un transport en service | S |
| I4 | L'écran *Administration → Intégrations*, les formulaires filtrés ; la documentation en anglais et en français | M |
