# Rapport d'Audit Approfondi : Documentation, Code Source & Sécurité

* **Projet :** Vectispire — ASPM & Plan de Contrôle de Sécurité Logicielle
* **Date :** 26 août 2026, 19:40
* **Commit audité :** `caa11096` (`develop`)
* **Périmètre :** les cinq axes de [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)

> **Treizième passage, le quatrième de la journée.** Les trois précédents ont visé l'autorisation,
> la crypto, le contrat d'empreinte et ADR-0007. Celui-ci vise le dernier artefact que treize
> passages ont nommé sans jamais le confronter au code : **le modèle de menaces STRIDE**.
>
> Un modèle de menaces n'est pas de la documentation. C'est une liste d'affirmations sur ce qui
> vous protège, lue par quelqu'un qui signera quelque chose sur cette base.

---

## 0. Ce qui a été exécuté

| commande | résultat |
|---|---|
| `./gradlew check` | **vert** |
| `./gradlew integrationTestAll --rerun-tasks` | **vert sur les trois moteurs** |
| `npx ng test --no-watch` | **23 fichiers, 146 tests** |
| `npx playwright test` | 13 sur 13 (plus tôt aujourd'hui, navigateur réel) |

---

## 1. Synthèse

| Domaine | Note | Ce qui la fixe |
|---|:---:|---|
| **Documentation & Architecture** | **8,4 / 10** | **Le modèle STRIDE décrit une protection qui n'existe pas**, dans les deux langues |
| **Sécurité & Cryptographie** | **8,5 / 10** | Le bac à sable tient et est prouvé ; le repli SSH hôte est actif par défaut |
| **Qualité du Code** | **8,6 / 10** | ADR-0007 refermée ce matin ; rien de neuf trouvé |
| **Conformité & Standards** | **9,3 / 10** | Inchangé |
| **Vérification exécutée** | **9,0 / 10** | Toujours aucun nocturne vert |

La documentation baisse de 9,2 à 8,4. **Le terrain ne s'est pas dégradé** : douze passages avaient
noté un artefact qu'ils n'avaient pas confronté au code.

---

## 2. 🔴 E1 — le modèle de menaces annonce une mitigation désactivée, qui est activée

`STRIDE_THREAT_MODEL`, processus **P2 — Orchestrateur de scan**, dans les deux langues :

| Menace | Mitigation annoncée |
|---|---|
| *L'orchestrateur utilise la clé SSH de l'hôte pour cloner des dépôts réservés* | **« Désactivation par défaut de la clé hôte (`host-ssh: false`) »** |

Le défaut réel, dans [`application.yaml`](../../../vectispire-java/vectispire-core/src/main/resources/application.yaml) :

```yaml
# Un dépôt sans clé de déploiement attachée retombe sur le ~/.ssh de cette machine.
host-ssh: ${VECTISPIRE_HOST_SSH:…:true}
```

**`true`.** Et `docker-compose.yml` ne se contente pas de l'activer — il **fournit les clés**, au
plan de contrôle *et* à l'agent :

```yaml
- ${HOME}/.ssh:/home/vectispire/.ssh:ro
```

Donc le fichier de déploiement livré met en place exactement les trois conditions du scénario que
le modèle dit couvrir : le repli est actif, les clés de l'opérateur sont montées, et un dépôt sans
clé propre les utilisera.

### Pourquoi c'est un 🔴 et pas une coquille

Un modèle de menaces est lu par un auditeur externe, un client en revue de sécurité, un
responsable qui signe. Il n'a pas de raison d'aller vérifier `application.yaml` : c'est
précisément le travail que le document prétend avoir fait pour lui. Une mitigation annoncée et
absente est pire qu'une absence de mitigation — elle consomme l'attention qui aurait servi à la
poser.

Et **aucun test n'épingle ce défaut**, dans un sens ou dans l'autre. Il peut basculer sans que rien
ne le dise.

### Ce qui n'est pas à moi de trancher

Passer le défaut à `false` casserait les installations qui comptent sur le repli : un dépôt sans
clé de déploiement cesserait de se cloner. C'est un arbitrage d'exploitant.

**Ce qui n'est pas un arbitrage**, c'est que le document cesse d'annoncer un contrôle qui n'existe
pas. Deux issues acceptables, une seule inacceptable — celle d'aujourd'hui.

---

## 3. Ce qui a été confronté au code et tient

Le même balayage a vérifié les autres affirmations du modèle, et elles résistent :

| affirmation STRIDE | vérification |
|---|---|
| « Aucun conteneur de scanner ne monte le socket Docker » | vrai — les chemins `docker.sock` du code sont la **découverte du démon** par le plan de contrôle, pas des montages |
| « Isolation réseau totale (`network: none`) » | `withNetworkMode(request.network() ? "bridge" : "none")`, et `ContainerHardeningTest` épingle les deux : pas de réseau par défaut, **et** qu'en demander un ne desserre rien d'autre |
| « `cap_drop: ALL`, `no-new-privileges`, `read-only` » | capturés sur le `HostConfig` réel par le même test |
| « Configuration imposée côté serveur » (ADR-0006) | le scanner de secrets passe son propre `--config` |
| « Zéro pilote JDBC sur le classpath de l'agent » | fait du graphe de build, et `AgentIsolationTest` interdit l'import |
| « `@PreAuthorize` et vérification stricte des rôles » | vrai : `@RequiresAdministrator` et consorts sont des méta-annotations bâties dessus |

C'est la moitié du travail d'un audit et elle mérite d'être écrite : **le modèle est
majoritairement exact**, ce qui rend l'entrée fausse d'autant plus coûteuse.

---

## 4. Recommandations

| # | Action | Vérifié comment |
|---|---|---|
| 🔴 1 | Aligner le modèle STRIDE et la réalité — **dans les deux langues**. Soit le défaut passe à `false` avec sa note de migration, soit le document énonce la posture réelle et le contrôle compensatoire | **mesuré** : doc = `false`, `application.yaml` = `true`, `docker-compose.yml` monte `${HOME}/.ssh` |
| 🟠 2 | Un test qui épingle le défaut de `host-ssh`, quel qu'il soit | mesuré : aucun test ne le mentionne |
| 🟡 3 | Confronter les autres tableaux STRIDE aux entités qui n'existaient pas quand il a été écrit (webhook de ticketing, chemins d'attaque, SCIM) | non fait : ce passage a vérifié les affirmations présentes, pas les absences |
