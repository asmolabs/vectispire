# 0045 — Sur un cluster sans Docker, les agents lancent chaque scanner dans un pod, dans un espace de noms à eux

**Date :** 2026-10-25 · **Statut :** acceptée · **Amende :** [0038](0038-deploying-on-kubernetes.md) · **S'appuie sur :** [0003](0003-long-polling-for-agents.md), [0007](0007-none-is-not-an-empty-list.md), [0017](0017-custom-checks-as-container-images.md), [0018](0018-the-docker-socket-is-never-mounted.md) · **Décideur :** Laurent Boucher

## Contexte

Chaque scanner, plugin de scan et plugin de rapport tourne aujourd'hui dans un conteneur Docker, créé par
`ContainerRunner` (`vectispire-common/.../scanning/ContainerRunner.java`) sous une seule forme fermée :
aucune capacité, aucun nouveau privilège, système de fichiers racine en lecture seule, l'uid du
propriétaire de l'espace de travail, pas de réseau sauf si l'étape en a besoin, limites de mémoire, de
CPU et de processus, un conteneur neuf à chaque exécution, supprimé après elle. La décision
[0038](0038-deploying-on-kubernetes.md) plaçait les agents d'une installation Kubernetes soit sur un hôte
Docker hors du cluster, soit dans le cluster à côté d'un sidecar `docker:dind` privilégié.

La première installation de production tourne **dans un cluster sans aucun Docker** (décidé par le
responsable du produit le 2026-10-25, à la place des VM Docker Compose choisies le 2026-10-14) : ni
démon, ni pod privilégié, ni VM à côté du cluster. Aucune des deux places de 0038 n'y existe, et une
analyse n'a rien pour lancer ses scanners.

L'[étude du 2026-10-16](../../../analysis/fr/2026-10-16_etude_executeur_kubernetes.fr.md) a chiffré un
exécuteur Kubernetes et posé les conditions pour le construire ; la première — une installation nommée
dans un cluster qui interdit les pods privilégiés — est remplie.

Trois formes moins coûteuses ont été pesées le 2026-10-25 et écartées :

- **Les scanners en sidecars durables du pod de l'agent.** Aucune permission Kubernetes, mais les
  conteneurs d'un pod sont fixés à son démarrage : un plugin de scan — une image qu'une tâche nomme (0017)
  — ne peut pas tourner, le plugin de scan de l'installation compris ; les conteneurs d'un pod partagent
  son réseau, donc chaque scanner reçoit celui de l'agent ; et un sidecar survit à son exécution, donc un
  scanner compromis par un dépôt hostile reste en place pour lire les dépôts suivants. Trois propriétés de
  la forme fermée perdues.
- **Les scanners en processus dans l'image de l'agent.** Un scanner exploité par un dépôt tournerait
  dans le même conteneur que les clés de déploiement et les jetons que l'agent descelle pour le clone.
- **Podman sur une VM**, qui accepterait sans doute l'agent actuel tel quel : exclu par l'installation.

## Décision

1. **L'exécuteur reçoit une couture, et une implémentation Kubernetes derrière.** Le contrat de
   `ContainerRunner` — exécuter un `ContainerRun`, exporter une image, se connecter à un registre pour une
   exécution, borner une sortie, dire si le moteur est disponible — devient une interface, avec
   l'exécuteur Docker d'aujourd'hui et un exécuteur Kubernetes. L'agent choisit par configuration
   (`vectispire.agent.executor: docker | kubernetes`). **Le plan de contrôle n'a jamais l'exécuteur
   Kubernetes** : il détient `ENCRYPTION_KEY`, et un droit de lancer des pods à côté de lui permettrait à
   qui compromet le plan de contrôle de lancer des images arbitraires dans le cluster, la clé en main
   (0003, 0038). Sur Kubernetes, le worker intégré reste éteint (`VECTISPIRE_EMBEDDED_WORKER=false`), comme
   le dit 0038.
2. **Un pod par exécution, comme aujourd'hui un conteneur par exécution.** Le pod porte exactement chaque
   propriété de la forme fermée que Kubernetes sait exprimer par pod : `capabilities.drop: [ALL]`,
   `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `runAsNonRoot` avec l'uid et le gid du
   propriétaire de l'espace de travail, `seccompProfile: RuntimeDefault`, limites de mémoire et de CPU
   égales aux demandes, `activeDeadlineSeconds` pour le délai, `automountServiceAccountToken: false`,
   l'image par digest, et des étiquettes nommant le scanner, l'étape et l'analyse. Il est supprimé après
   son exécution, et l'agent balaie son étiquette au démarrage pour ce qu'un arrêt brutal a laissé.
3. **Dans un espace de noms à lui, sous un Role qui n'atteint rien d'autre.** Les pods tournent dans un
   espace de noms dédié étiqueté `pod-security.kubernetes.io/enforce: restricted` : le serveur d'API refuse
   lui-même un pod privilégié, un `hostPath`, le réseau de l'hôte ou un utilisateur root, quoi que l'agent
   demande. Le compte de service de l'agent détient, dans cet espace de noms seulement : `pods` `create`,
   `get`, `list`, `watch`, `delete` ; `pods/exec` `create` ; `pods/log` `get`. Rien à l'échelle du cluster,
   aucun secret. Le chart rend le Role, et un test fige ses règles : `pods/exec` écrit plus large par un
   opérateur atteindrait d'autres charges.
4. **L'espace de travail entre, et le rapport sort, par `exec`.** L'agent clone comme aujourd'hui, puis
   envoie l'espace de travail dans l'`emptyDir` du pod par `tar` sur `exec`, dans un conteneur d'init qui
   l'attend ; le scanner démarre une fois qu'il est là, et un « holder » — un second conteneur ordinaire qui
   survit au scanner — garde le pod en marche pour que son rapport soit lu par une lecture `exec` plafonnée.
   Pas un sidecar natif, comme le prévoyait l'étude : Kubernetes les arrête dès que les conteneurs ordinaires
   du pod sont sortis, et le rapport partirait avec eux. **Jamais
   depuis les journaux du pod** : le kubelet les fait tourner (10 Mio par défaut), et un rapport coupé lu
   avec indulgence, c'est de nouveau le défaut « absent contre vide ». Au-delà du plafond, c'est un échec,
   pas une troncature, comme aujourd'hui. Aucun secret de clone n'atteint jamais un pod d'analyse.
5. **Pas de réseau sauf si l'étape en a besoin, et c'est prouvé.** Les étapes hors ligne — chaque
   scanner sur une arborescence, l'appariement, les plugins qui ne déclarent pas de réseau — portent une
   étiquette à laquelle une NetworkPolicy refuse toute sortie. Les étapes en réseau — la mise à jour de la
   base de l'appariement, la copie d'image, cosign, les plugins qui déclarent du réseau — en portent une
   autre, autorisée vers l'extérieur sauf les plages du cluster, privées et de métadonnées. Une
   NetworkPolicy que le CNI n'applique pas est acceptée puis ignorée : **l'agent sonde au démarrage** — il
   lance un pod hors ligne qui tente de sortir, et refuse d'analyser s'il y parvient.
6. **Trois propriétés de la forme fermée ne se règlent pas par pod, et sont acceptées avec leurs
   compensations :** la limite de processus (le `podPidsLimit` du kubelet, réglé sur le pool de nœuds
   dédié que le chart exige) ; `noexec` et `nosuid` sur l'espace de travail temporaire (aucune option de
   volume n'existe) ; et `fsize` et le nombre d'inodes d'une sortie bornée, que remplace un `emptyDir` en
   mémoire avec `sizeLimit` — compté dans la mémoire du pod, `ENOSPC` au-delà de sa taille — avec la lecture
   plafonnée derrière.
7. **La base de l'appariement vit sur un volume ReadWriteOnce de l'agent.** Les pods des scanners sont
   placés sur le nœud de l'agent et la montent en lecture seule ; le téléchargement tourne dans un pod en
   réseau sur ce nœud, sous le même verrou de fichier qu'aujourd'hui. Pas de système de fichiers réseau
   partagé : les verrous sur NFS dépendent de sa configuration.
8. **Une cible image est copiée, pas tirée par un analyseur.** Une étape `crane` (ou `skopeo`) épinglée
   copie l'image en disposition OCI dans l'espace de travail, l'identifiant du registre lui étant remis en
   fichier ; Syft et Grype lisent la disposition hors ligne. Les laisser tirer donnerait réseau et
   identifiants aux analyseurs de métadonnées hostiles. Un jeu de référence confronte Syft sur une
   disposition OCI à Syft sur une archive Docker : **les empreintes ne doivent pas bouger**.
9. **Jamais vide.** Chaque issue Kubernetes est un échec nommant l'étape — une image qui ne se tire pas,
   un pod que personne ne peut placer, `OOMKilled`, le délai, une éviction, une lecture au-delà de son
   plafond, un pod supprimé en route — donc l'étape est absente et son backlog reste tel quel (0007).
10. **Construit d'abord dans l'agent Java.** L'agent Rust n'est pas prêt à servir une installation ;
    l'exécuteur sera porté avec le reste quand il le sera.

**Avant qu'il analyse quoi que ce soit pour l'installation**, tout ce qui suit est vérifié, et les
résultats sont écrits dans cette décision : le cluster tourne dans une version de Kubernetes encore
maintenue en amont ; sur lui, un `emptyDir` en mémoire avec `sizeLimit` est mesuré pour répondre `ENOSPC` plutôt
qu'une éviction ; son CNI applique les NetworkPolicy, comme la sonde le montre ;
`scripts/composition-scan-check.sh MODE=agent` donne des **constats identiques** avec l'exécuteur Docker et
l'exécuteur Kubernetes, analyse d'image comprise, jeux de référence inchangés ; et une revue de sécurité
du Role, de l'espace de noms et des politiques ne trouve rien au-dessus de faible.

## Conséquences

- **Plus aucun Docker** dans une installation Kubernetes qui choisit cet exécuteur ; le sidecar
  Docker-in-Docker de 0038 reste pour les clusters qui admettent les pods privilégiés et le préfèrent.
- **L'agent détient un droit Kubernetes.** Il est plus étroit que ce qu'un agent détient aujourd'hui — un
  proxy de socket qui ne peut pas refuser un montage de `/`, ou un démon privilégié root sur son nœud —
  mais `pods/exec` est un verbe fort : d'où le Role rendu par le chart et figé par un test.
- **Chaque exécution coûte un pod.** Le placement et le tirage des images ajoutent de la latence ; le
  chart tire en `IfNotPresent` sur le pool dédié, et un pré-tirage pourra suivre.
- **Le coût est de 35 à 55 jours-développeur** (l'étude, §9) : la couture, la spécification du pod et son
  cycle de vie, la copie à l'aller et au retour, les limites, la copie d'image et son jeu de référence, le
  volume de la base, les politiques et leur sonde, le chart, et une tâche nocturne sur un cluster `kind`
  qui lance la vérification de composition contre cet exécuteur.
- **Tant qu'il n'est pas livré, l'installation n'a pas d'analyses intégrées.** Elle démarre en 0.11.1
  sans agent ; les plugins de rapport répondent 409 comme 0038 l'a décidé, et restent une décision à part.
- Un client Kubernetes devient une dépendance de l'agent, relue par `gradle/verification-metadata.xml`
  comme toute autre.

## Maquette, 2026-10-25

`scripts/k8s-executor-spike.sh` déroule le mécanisme avec kubectl et fait les mesures ci-dessus ; il est
fait pour tourner aussi sur le cluster cible. Sur un cluster k3s jetable, Kubernetes 1.31, les quatre
vérifications sont passées :

1. Pod Security `restricted`, appliqué à l'espace de noms, refuse un pod qui tourne en root.
2. Un pod sous la NetworkPolicy hors ligne ne peut pas sortir (le contrôleur de politiques de k3s
   l'applique).
3. Une écriture au-delà du `sizeLimit` (8 Mio) d'un `emptyDir` en mémoire s'arrête à la limite sur
   `ENOSPC` ; le pod n'est pas évincé.
4. Une étape d'analyse de bout en bout : un espace de travail copié dans un conteneur d'init en attente par
   `exec` et `tar`, l'image gitleaks épinglée lancée dessus hors ligne sous `restricted` en uid 1000, son
   rapport relu depuis le holder par `exec` à travers une lecture plafonnée, et le jeton planté dans
   l'espace de travail trouvé dedans.

Elle a corrigé l'étude sur un point, repris au point 4 de la décision : le holder est un conteneur
ordinaire, puisqu'un sidecar natif est arrêté avec le pod, et le rapport avec lui — ce qui retire aussi le
plancher de version des sidecars natifs. Pas encore mesuré : le cluster cible lui-même, et la parité des
constats entre les deux exécuteurs, qui demande l'exécuteur Java.
