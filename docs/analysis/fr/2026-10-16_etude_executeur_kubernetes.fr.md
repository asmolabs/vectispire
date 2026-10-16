# Étude : lancer les analyses sur Kubernetes plutôt que sur Docker

**Date :** 16 octobre 2026 · **Arbre étudié :** `develop` @ `312b7cc8`, et les fondations du portage
Rust (`feat/rust-agent` @ `c93eef175`) · **Statut :** proposition, aucun code écrit · **Amenderait :**
la [décision 0038](../../architecture/fr/decisions/0038-deploying-on-kubernetes.md)

---

## 0. En un paragraphe

Aujourd'hui, chaque scanner, plugin de scanner et plugin de rapport s'exécute comme un conteneur
Docker. C'est `ContainerRunner` qui le crée (`vectispire-common/.../scanning/ContainerRunner.java`,
820 lignes), dans une seule forme fermée (`ContainerRun`, 201 lignes). Il passe par un proxy de socket
sur la machine qui analyse ([0018](../../architecture/fr/decisions/0018-the-docker-socket-is-never-mounted.md)).
Un **backend Kubernetes** créerait plutôt ces exécutions comme des pods dans un espace de noms dédié,
sans aucun démon Docker. La décision 0038 l'a écarté le 2026-10-03, « pas pour octobre », pour trois
raisons :
- la borne de sortie devient une éviction au lieu d'une limite du noyau ;
- le processus qui crée les pods a besoin de droits RBAC ;
- l'exécuteur est à réécrire.

Cette étude reprend ces raisons face au code et conclut :

- **La réécriture est réelle mais bornée :** **33 à 55 jours-développeur** pour un backend (§9),
  dans l'agent Java ou dans l'agent Rust.
- **Seul l'agent doit la porter**, jamais le plan de contrôle.
- **C'est plus sûr que ce qu'utilisent aujourd'hui les agents dans un cluster.** Ils utilisent le
  sidecar Docker-in-Docker, en option, qui est un conteneur privilégié, donc root sur son nœud. Avec
  un Role limité à un espace de noms et la Pod Security Admission `restricted`, un agent compromis ne
  peut lancer que des pods non privilégiés, dans un seul espace de noms.
- **C'est aussi plus étroit que le rayon d'impact d'une VM d'agent :** le proxy de socket, comme le
  dit `docker-compose.yml` lui-même, « réduit la surface, il ne trace pas de frontière ».
- **Trois propriétés de la forme fermée ne s'expriment pas par pod** et sont à compenser ou à
  accepter (§3) : la limite de processus par conteneur, le `noexec` de l'espace de travail
  temporaire, et la limite d'inodes.

**Recommandation :** ne pas le construire pour la production, qui tourne sur des VM Docker Compose
(décidé le 2026-10-14) et n'en a pas besoin. Le construire **une seule fois, dans l'agent Rust**, une
fois que cet agent a passé sa période de conformité côte à côte, et seulement quand une installation
nommée a besoin d'agents dans un cluster qui interdit les pods privilégiés. Les critères de décision
sont au §11.

---

## 1. Qui en a besoin, et quand

| Installation | Où tournent les analyses aujourd'hui | En a-t-elle besoin ? |
|---|---|---|
| Production (fin octobre 2026) | Agents sur des VM Docker Compose, un par instance | **Non** : une VM a son propre démon |
| Kubernetes, agents hors du cluster (recommandation de 0038) | Agents sur un hôte Docker | Non |
| Kubernetes, agents dans le cluster (0038, réponse 2, en option) | Pod d'agent + sidecar `docker:dind` privilégié sur un groupe de nœuds dédié | **Oui : c'est ce qu'il remplace** |
| Un cluster dont la politique interdit les pods privilégiés (courant sur les clusters managés et durcis) | Impossible aujourd'hui | **Oui : seul moyen d'analyser dans le cluster** |

Le besoin est donc conditionnel. Rien dans le plan d'octobre n'en dépend.

## 2. Où tourne l'exécuteur : seulement l'agent

**Le plan de contrôle ne doit jamais créer de pods d'analyse.** Il détient `ENCRYPTION_KEY`, qui
déchiffre toutes les clés de déploiement que Vectispire stocke (décision 0003). 0038 a déjà refusé
de donner à ce processus des droits RBAC pour créer des pods, et rien ici ne change cela. Un droit de
créer des pods sur le plan de contrôle permettrait, s'il était compromis, de lancer n'importe quelle
image dans le cluster, clé en main. Le worker intégré reste donc une fonction Docker seulement. Sur
Kubernetes, `VECTISPIRE_EMBEDDED_WORKER=false` reste la règle.

L'agent ne détient ni accès à la base ni clé, par construction du graphe de build (0003 ; le portage
Rust le conserve par un test sur `cargo metadata`). C'est le bon endroit pour un droit qui démarre des
pods, comme il est aujourd'hui le bon endroit pour un accès Docker.

## 3. La forme fermée traduite en pod

Lu dans `ContainerRunner.closedHostConfig` (≈ lignes 329–367), `create` (≈ 371–410) et
`ScannerLimits` (`DEFAULT` : 2 Gio de mémoire, 512 processus, 15 min, 256 Mio de sortie).

| Propriété de `ContainerRun` (Docker) | Équivalent pod / Job | Parité |
|---|---|---|
| `CapDrop: ALL` | `securityContext.capabilities.drop: [ALL]` | exacte |
| `no-new-privileges` | `allowPrivilegeEscalation: false` | exacte |
| `ReadonlyRootfs` | `readOnlyRootFilesystem: true` | exacte |
| utilisateur = propriétaire de l'espace de travail (`runningAsOwnerOf`) ; aucun scanner en root | `runAsUser`/`runAsGroup`, `runAsNonRoot: true` | exacte ; tous les scanners sont déjà non root, donc la PSA `restricted` les admet tous |
| seccomp par défaut | `seccompProfile: RuntimeDefault` | exacte (exigé par `restricted`) |
| `Memory`, `NanoCPUs` | `resources.limits.memory` / `cpu` (requests = limits) | exacte |
| `PidsLimit: 512` | **aucun champ par pod.** Seulement le `podPidsLimit` du kubelet, réglé par nœud | **écart** : il faut un groupe de nœuds dédié réglé ainsi |
| `NetworkMode: none` | une NetworkPolicy qui refuse toute sortie aux pods étiquetés hors ligne | **au niveau du pod, pas du conteneur**, et silencieusement absente si le CNI n'applique pas les NetworkPolicy (§7) |
| `NetworkMode: bridge` (mise à jour de la base, cosign, plugins qui déclarent le réseau) | une seconde étiquette, qui choisit une politique autorisant la sortie sauf vers les plages du cluster, privées et de métadonnées | même intention ; une NetworkPolicy ne sait pas nommer des hôtes DNS |
| tmpfs `/tmp` et `HOME`, `rw,noexec,nosuid,mode=1777,size=512m` | `emptyDir {medium: Memory, sizeLimit: 512Mi}` | **écart** : aucune option de montage `noexec`/`nosuid` pour les volumes. Taille : voir §5 |
| étiquette `dev.vectispire.scanner` | étiquettes du pod (+ identifiant d'analyse, étape) | exacte, et mieux : `ownerReferences` vers le pod de l'agent |
| délai (`waitFor`, 15 min par défaut) | `activeDeadlineSeconds` + l'attente de l'agent | exacte |
| suppression explicite, durée de vie du conteneur témoin après un plantage | `ttlSecondsAfterFinished` (Jobs) ou suppression explicite + balayage par étiquette au démarrage de l'agent | exacte |
| image par digest (`ScannerImages`) | `image: nom@sha256:…`, `imagePullPolicy: IfNotPresent` | exacte |
| connexion au registre (`RegistryLogin`, fichier `DOCKER_CONFIG`) | un fichier copié (§4), jamais un `imagePullSecret` partagé avec d'autres charges | voir §6 |
| aucun compte de service | `automountServiceAccountToken: false`, un compte sans Role | exacte |
| `Ulimit fsize` sur les sorties bornées | **aucun champ** | écart, compensé par la lecture plafonnée (§5) |
| nombre d'inodes de la sortie bornée (`OUTPUT_INODES`) | **aucun champ** (`nr_inodes` n'est pas exposé) | écart accepté : la limite mémoire borne le coût |

Tout ce qui est « exact » ci-dessus est appliqué par le kubelet et le runtime, les mêmes mécanismes
que ceux qu'utilise Docker. Les trois écarts sont le prix du changement et doivent figurer dans l'ADR.

## 4. Comment l'espace de travail atteint le scanner

Aujourd'hui l'espace de travail est un répertoire de l'hôte, en mode 0700, appartenant à l'uid 1000
de l'agent, monté par bind dans chaque conteneur de scanner. Le démon résout ce bind sur son propre
hôte. C'est pourquoi les agents en cluster de 0038 montent le répertoire de travail au même chemin
dans l'agent et dans le démon. Un pod sur un autre nœud ne voit pas les fichiers de l'agent.

| Option | Pour | Contre |
|---|---|---|
| **A. Un volume partagé ReadWriteMany** (NFS, CephFS) | le plus proche d'un bind | il faut une classe de stockage RWX, que beaucoup de clusters n'ont pas ; chaque espace de travail et le code du dépôt traversent le réseau sur un partage (0038 a refusé la même chose pour les rapports, option C) ; la propriété des fichiers sur NFS rouvre la question des uid |
| **B. Un conteneur d'init qui clone** | pas de copie | les secrets de clone (clé de déploiement, jeton HTTPS) seraient remis à un pod de l'espace d'analyse, et le code de clone tournerait deux fois ; l'épinglage de la clé d'hôte et le refus des redirections seraient à refaire dans cette image |
| **C. Copie aller et retour par `exec` + tar** (ce que fait `kubectl cp`) | le pod n'a **aucun réseau** ; la propriété est celle du `runAsUser` du conteneur qui reçoit, ce qui **ferme l'écart 0700/uid que 0038 a mesuré avec Docker rootless** | il faut `pods/exec` dans le Role (limité à l'espace d'analyse) ; la copie est un flux que l'agent doit plafonner |
| **D. Un sidecar qui sert l'espace de travail en HTTP** | pas de droit `exec` | le pod a besoin du réseau vers l'agent, et une NetworkPolicy s'applique au pod entier, donc le scanner l'a aussi |
| **E. Conteneurs éphémères** | aucun pour cet usage | on ne peut pas leur donner les volumes et ressources voulus ; ils sont faits pour le débogage |

**Recommandé : C.** C'est l'équivalent direct de ce que `ContainerRunner` fait déjà avec l'API
d'archive pour les sorties bornées (`copyArchiveFromContainerCmd` sur le conteneur témoin). Une étape
se déroule ainsi :

1. L'agent crée le pod, avec :
   - un `emptyDir` pour l'espace de travail ;
   - un **témoin** en sidecar natif : une image minimale épinglée qui dort, `restartPolicy: Always`
     dans `initContainers`, Kubernetes ≥ 1.29 ;
   - un conteneur d'init ordinaire qui attend un fichier marqueur ;
   - le scanner comme conteneur principal.
2. L'agent envoie l'espace de travail dans le conteneur d'init en attente par `exec tar -x`, puis
   écrit le marqueur, et le scanner démarre.
3. Le scanner écrit son rapport dans l'`emptyDir`, et le témoin garde le pod en vie après la fin du
   scanner.
4. L'agent lit le rapport par `exec cat`, avec le même lecteur plafonné qu'aujourd'hui : au-delà du
   plafond, c'est un **échec, pas une troncature**, comme le dit `ContainerRunner`. Puis il supprime
   le pod.

**Ne pas lire les rapports dans les journaux du pod.** Le kubelet fait tourner les journaux des
conteneurs à `containerLogMaxSize`, 10 Mio par défaut. Un SBOM de 200 Mo lu par `pods/log` serait
coupé sans bruit, et un JSON coupé lu avec indulgence est exactement le défaut absent/vide corrigé en
0.11.1. Les journaux ne servent qu'au stderr, que le runner plafonne déjà à 1 Mio (`STDERR_BYTES`) et
que les scanners citent sur 2 000 caractères.

## 5. La sortie bornée sans volume tmpfs limité en taille

`ContainerRun.BoundedOutput` existe parce qu'un outil écrivait à côté de son rapport jusqu'à remplir
le disque de l'exécuteur. Sa borne est un volume tmpfs avec `size=`, gardé en vie par un témoin, plus
`fsize` et un nombre d'inodes : trois limites du noyau.

- **Un `emptyDir` sur disque avec `sizeLimit` est appliqué par éviction.** Le kubelet le remarque à
  son passage de maintenance et évince le pod, donc un outil peut dépasser pendant quelques secondes.
  C'est l'objection de 0038, et elle vaut pour le disque.
- **Un `emptyDir` en `medium: Memory` est un tmpfs**, dont les pages sont imputées au cgroup mémoire
  du pod, donc bornées par la limite mémoire, par le noyau. Les versions récentes de Kubernetes le
  montent en plus avec `size=` égal à `sizeLimit` (le comportement `SizeMemoryBackedVolumes`), ce qui
  donne `ENOSPC` comme aujourd'hui. **C'est à vérifier sur la version du cluster cible.** Là où c'est
  vrai, l'objection d'éviction de 0038 tombe pour les sorties en mémoire.
- **Reste un écart :** `fsize` (un fichier creux `truncate -s 1T` ne coûte rien sur un tmpfs) et le
  nombre d'inodes. Les deux sont compensés par le lecteur : le `exec cat` de l'agent est plafonné au
  plafond de la sortie et échoue au-delà, exactement comme `OutputArchive.read` aujourd'hui.

## 6. Les scanners un par un

- **Gitleaks, Checkov, Semgrep, Syft sur une arborescence :** hors ligne ; l'espace de travail entre,
  le rapport sort. L'option C les couvre tels quels. Les règles de Semgrep et de Checkov sont déjà
  placées dans l'espace de travail (`Workspace.rules`, `RulePlacement`), donc rien d'autre à monter.
- **Grype et sa base** (`VulnerabilityDatabase`, 408 lignes). La base fait quelques Go, avec un
  verrou `FileChannel` pour qu'un seul téléchargement ait lieu à la fois par hôte. Le portage Rust
  prend le même verrou POSIX, donc les deux agents s'accordent.
  - **Recommandé :** un **PVC ReadWriteOnce** appartenant à l'agent. Les pods de scanner sont placés
    **sur le nœud de l'agent** (affinité de pod) et le montent en lecture seule ; RWO admet plusieurs
    pods sur un même nœud. Le téléchargement tourne comme un pod avec réseau sur ce nœud.
  - Le verrou reste un verrou POSIX local, sur le système de fichiers d'un seul nœud.
  - **Éviter RWX/NFS ici :** les verrous POSIX sur NFS dépendent de la configuration du serveur et
    du client.
- **Analyse d'images** (`DependencyScanner.exportImage`, `ContainerRunner.exportImage` :
  `pullImageCmd` + `saveImageCmd`). Il n'y a pas de démon pour tirer et sauvegarder l'image.
  - **Recommandé :** une étape avec réseau qui lance une image **`crane` ou `skopeo` épinglée**. Elle
    copie l'image dans une disposition OCI de l'espace de travail, avec la connexion au registre
    copiée comme fichier ; Syft et Grype lisent ensuite la disposition hors ligne.
  - Laisser Syft ou Grype tirer eux-mêmes depuis le registre donnerait des secrets et du réseau aux
    analyseurs de métadonnées hostiles.
  - **Une vérification par jeu de référence est obligatoire :** Syft sur une disposition OCI contre
    Syft sur une archive Docker. Les champs de paquets doivent être égaux, mais les métadonnées de
    source diffèrent, et les empreintes ne doivent pas bouger (AGENTS.md, « fingerprint »).
- **Cosign** (`ImageSignatureVerifier`) tourne déjà comme un conteneur avec réseau et un fichier de
  connexion. Seul change le transport de la clé et du fichier de connexion (option C).
- **Plugins de scanner** (`PluginScanner` ; [0017](../../architecture/fr/decisions/0017-custom-checks-as-container-images.md)) :
  même forme, réseau seulement si le manifeste le demande, sortie bornée comme au §5.
- **Plugins de rapport** (`ReportPluginRenderer`, [0035](../../architecture/fr/decisions/0035-report-plugins.md)) : voir §8.

## 7. RBAC, rayon d'impact et isolement

**Le Role** vit dans un espace de noms dédié, par exemple `vectispire-scans`, lié au compte de
service de l'agent :
- `pods` : `create`, `get`, `list`, `watch`, `delete` ;
- `pods/exec` : `create` ;
- `pods/log` : `get` ;
- rien d'autre : pas de secrets, pas de déploiements, rien à l'échelle du cluster.

**L'espace de noms** porte l'étiquette `pod-security.kubernetes.io/enforce: restricted` : le serveur
d'API refuse lui-même un pod privilégié, un `hostPath`, le réseau de l'hôte ou un utilisateur root,
quoi que demande l'agent.

| Un agent compromis peut… | Aujourd'hui : VM + proxy de socket | Aujourd'hui : DinD en cluster (0038 réponse 2) | Backend Kubernetes |
|---|---|---|---|
| devenir root sur son hôte ou son nœud | **oui** : `POST /containers/create` avec un bind de `/`, que le proxy ne peut pas refuser (`docker-compose.yml`) | **oui** : un démon privilégié | **non** : PSA `restricted` |
| lancer des images arbitraires | oui, sur sa VM | oui, sur son nœud | oui, comme pods restreints dans un seul espace de noms |
| lire d'autres charges | ce que contient son hôte | celles du nœud | **rien** : autres espaces de noms, aucun Role |
| faire un exec dans des pods | sans objet | sans objet | **seulement dans l'espace d'analyse**, donc ses propres pods |

**Les mesures d'isolement que porterait le chart :**
- un `ResourceQuota` et un `LimitRange` sur l'espace de noms ;
- un groupe de nœuds dédié (taint et `nodeSelector`) portant le réglage `podPidsLimit` ;
- les deux NetworkPolicy ;
- en option, un `runtimeClassName` gVisor ou Kata, en défense en profondeur contre les évasions.

**Ne jamais sauter en silence.** Sur un CNI qui ne les applique pas, une NetworkPolicy est acceptée
puis ignorée. L'agent doit donc **sonder au démarrage** : il lance un pod avec l'étiquette hors ligne,
tente une connexion sortante, et refuse d'analyser si elle réussit. Un scanner « sans réseau » sur le
papier et avec tout le réseau en fait, c'est le genre de vert que ce dépôt interdit.

## 8. Plugins de rapport : est-ce que cela débloque les options A et B de 0038 ?

En partie, et pas là où on l'espérerait.
- **Pas sur le plan de contrôle.** Y lancer les plugins de rapport comme pods mettrait un droit de
  création de pods à côté d'`ENCRYPTION_KEY`, ce que le §2 refuse. L'option A, un exécuteur distant
  piloté par le plan de contrôle, n'en devient donc pas moins chère.
- **Sur les agents (option B), oui pour la partie exécution.** Un agent doté de ce backend peut lancer
  un plugin de rapport comme pod restreint. Mais le vrai coût de l'option B est ailleurs :
  - l'export confidentiel scellé pour un agent désigné (les clés de 0031) ;
  - un nouveau type de travail d'agent ;
  - le résultat renvoyé et vérifié avant signature.

  Le backend n'y change rien. Les plugins de rapport restent donc une décision à part ; le backend
  retire seulement « et cet agent a besoin d'un démon Docker ».

## 9. Effort

En jours-développeur, pour un backend, avec une équipe qui connaît le code et Kubernetes. Les
parties 8 à 10 sont partagées si les deux agents l'ont un jour.

| # | Partie | Agent Java | Agent Rust |
|---|---|---|---|
| 1 | Point de séparation de l'exécuteur : une interface devant le runner, y compris `exportImage`, la connexion au registre, la sortie bornée, la disponibilité | 3–5 | 2–4 |
| 2 | Spécification de pod à partir de `ContainerRun` ; création, suivi, attente, délai, suppression ; `ownerReferences` ; balayage par étiquette au démarrage | 6–9 (client fabric8 : grosse dépendance nouvelle, revue de `verification-metadata.xml`) | 5–8 (`kube` + `k8s-openapi`, via `cargo deny`) |
| 3 | Espace de travail aller et rapport retour par `exec` + tar ; témoin en sidecar natif ; lectures plafonnées | 5–8 | 5–8 |
| 4 | Limites et écarts (§3, §5) ; correspondance des échecs (§10) avec tests | 3–5 | 3–5 |
| 5 | Export d'image avec `crane`/`skopeo` vers une disposition OCI ; Syft et Grype sur les dispositions ; jeu de référence ; transport pour cosign | 4–6 | 4–6 |
| 6 | Base de vulnérabilités sur un PVC RWO avec affinité de nœud ; pod de téléchargement | 2–4 | 2–4 |
| 7 | NetworkPolicy et sonde d'application au démarrage | 2–3 | 2–3 |
| 8 | Chart Helm : `agents.executor: kubernetes`, espace de noms avec étiquettes PSA, Role et RoleBinding, politiques, quota, groupe de nœuds, PVC ; tests de rendu et kubeconform | 3–5 | 3–5 |
| 9 | CI : un job kind (image de nœud épinglée par digest) qui lance `scripts/composition-scan-check.sh MODE=agent` sur ce backend, dans la nightly | 4–6 | 4–6 |
| 10 | ADR amendant 0038, docs en anglais et en français, revue de sécurité | 3–4 | 3–4 |
| | **Total** | **35–55** | **33–53** |

Le construire dans **les deux** agents coûte environ **20 à 30 jours de plus** (parties 1 à 7 à
refaire).

## 10. Sémantique des échecs : jamais vide

Chaque issue retombe sur ce que `ContainerRunner` lève déjà : une `ScannerFailureException` qui nomme
l'étape. L'étape est donc **absente** et ses types d'anomalies restent en l'état
([0007](../../architecture/fr/decisions/0007-none-is-not-an-empty-list.md)). Aucune ne peut devenir un
résultat vide.

| Issue Kubernetes | Traduite en |
|---|---|
| `ErrImagePull`, `ImagePullBackOff` après un court délai de grâce | échec : l'image n'a pas pu être tirée |
| `Unschedulable` après un délai d'attente | échec : aucun nœud ne peut lancer l'étape (quota, taints) |
| `OOMKilled` (code 137 avec cette raison) | échec : mémoire dépassée |
| `DeadlineExceeded` | `ScannerFailureException.timedOut`, comme aujourd'hui |
| `Evicted` (`sizeLimit` disque, pression sur le nœud) | échec : a écrit plus que permis, ou le nœud l'a repris |
| lecture plafonnée au-delà du plafond | échec, pas troncature, comme aujourd'hui |
| pod supprimé par quelqu'un d'autre, redémarrage de l'agent en cours d'étape | échec ; le balayage par étiquette nettoie les restes |
| code de sortie non nul | comme aujourd'hui : les règles du scanner sur son code de sortie |

**Observabilité :** chaque pod porte le scanner, l'étape et l'identifiant d'analyse. L'agent
journalise les événements du pod en cas d'échec, pour que le « pourquoi » se voie sans accès au
cluster.

## 11. Proposition de décision

**Ce que dirait l'ADR (amendant 0038) :** les agents peuvent lancer leurs analyses comme pods dans un
espace de noms dédié, sous PSA `restricted`, avec :
- un Role limité à cet espace de noms ;
- la copie aller et retour par `exec` ;
- des sorties en mémoire ;
- une sonde de démarrage qui refuse une NetworkPolicy non appliquée.

Les trois écarts sont acceptés avec leurs compensations : processus par groupe de nœuds, pas de
`noexec` sur l'espace temporaire, nombre d'inodes. Le plan de contrôle n'obtient jamais ce droit. Le
sidecar Docker-in-Docker devient la solution de repli pour les clusters trop anciens pour les
sidecars natifs.

**N'y aller que si toutes ces conditions sont réunies :**
1. Une installation nommée a besoin d'agents dans un cluster qui interdit les pods privilégiés. Sans
   elle, le travail n'a pas d'utilisateur.
2. Les clusters cibles sont en Kubernetes ≥ 1.29, pour les sidecars natifs. Sur leurs versions, un
   `emptyDir` en mémoire avec `sizeLimit` donne `ENOSPC`, et non une éviction, mesuré.
3. Leur CNI applique les NetworkPolicy, ce que la sonde de démarrage montre sur le vrai cluster.
4. `composition-scan-check.sh MODE=agent` donne **des constats identiques** sur les backends Docker et
   Kubernetes, avec les jeux de référence inchangés, y compris l'analyse d'image par disposition OCI.
5. Une revue de sécurité du Role, de l'espace de noms et des politiques ne trouve rien au-dessus de
   « faible ».

**Où le construire : dans l'agent Rust, une seule fois.** Le portage Rust est en cours, son crate de
conteneurs (`vectispire-rust/crates/container`, 519 lignes) est jeune, et son `ContainerRunner` est
un type concret : y ajouter le point de séparation maintenant coûte le moins. Le construire d'abord
en Java n'a de sens que si le critère 1 apparaît avant que l'agent Rust ait fini sa période côte à
côte. Dans ce cas, le construire en Java et le porter avec le reste.

## 12. Risques

- **`pods/exec` est un verbe puissant.** Il est ici limité à un espace de noms qui ne contient que
  les pods de l'agent. Un Role écrit plus large par un opérateur en ferait un exec sur d'autres
  charges ; le chart doit donc le rendre et un test doit figer ses règles.
- **Une NetworkPolicy non appliquée** donne tout le réseau en silence ; la sonde du §7 n'est pas
  facultative.
- **Latence :** un pod par étape, plus les tirages d'images (l'image de Semgrep fait 419 Mo
  compressée). Atténuation : `IfNotPresent` sur un groupe de nœuds dédié, éventuellement un DaemonSet
  de pré-tirage.
- **Écarts de versions** entre clusters (sidecars natifs, `sizeLimit` en mémoire).
- **Chaîne d'approvisionnement :** un client Kubernetes est une grosse dépendance dans les deux
  langages, revue par `verification-metadata.xml` ou `cargo deny`.
- **Empreintes :** la disposition OCI pour l'analyse d'images est le seul endroit où l'entrée du
  scanner change ; le jeu de référence la garde (§6).

## 13. Ce qui a été lu

- **Code :** `ContainerRunner`, `ContainerRun`, `ScannerLimits`, `Workspace`, `OutputArchive`, et
  les scanners de `scanning/scanners/` : `SecretsScanner`, `SastScanner`, `IacScanner`,
  `DependencyScanner`, `VulnerabilityDatabase`, `ImageSignatureVerifier`, `PluginScanner`,
  `ReportPluginRenderer`, `ScannerImages`.
- **Composition :** les notes sur le proxy de socket dans `docker-compose.yml`.
- **Décisions :** 0003, 0007, 0017, 0018, 0031, 0035 et 0038, avec ses réponses du 2026-10-03 et son
  amendement du 2026-10-10.
- **Rust :** le crate de conteneurs de `feat/rust-agent`.
- **Non exécuté :** les comportements Kubernetes cités au §5 (`sizeLimit` en mémoire), au §4
  (rotation des journaux par défaut) et au §7 (PSA) sont tirés des valeurs par défaut de la
  documentation de Kubernetes. Le critère 2 demande de les mesurer sur les clusters cibles.
