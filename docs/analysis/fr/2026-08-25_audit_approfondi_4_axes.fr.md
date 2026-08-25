# Audit Approfondi — Quatre Axes : Documentation, Sécurité, Code, Conformité (Français)

* **Projet :** Vectispire — Control Plane ASPM & Sécurité Logicielle
* **Date d'analyse :** 25 août 2026 (troisième passe)
* **Évaluateur :** Claude (Anthropic) — audit automatisé du code, de la sécurité et de la documentation
* **Périmètre :** Les quatre axes de [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md), chacun vérifié contre l'arbre et non contre les rapports précédents.
* **Rapports antérieurs :** [Audit Approfondi](2026-08-25_audit_approfondi_code_securite_doc.fr.md) (7,9) → [Post-Remédiation](2026-08-25_audit_post_remediation.fr.md) (8,9)

> **Pourquoi une troisième passe, et ce qu'elle apporte.** Les deux rapports précédents portaient sur le câblage de la sécurité et sur la remédiation qui a suivi. Plusieurs axes nommés par le prompt n'avaient jamais été vérifiés en profondeur : la *reproductibilité* du modèle C4, la complétude STRIDE, l'implémentation réelle d'ADR-0007, la promesse de déduplication multi-scanners, SCIM/OIDC et les formats de la chaîne d'approvisionnement. Cette passe les a attaqués, et **les deux constats les plus lourds de ce rapport viennent de ce terrain jusque-là inexploré** — dont un chemin de perte silencieuse de données sur le type de constat le plus sensible que le produit manipule.

---

## 📊 1. Tableau Récapitulatif des Notes

| Domaine évalué | Post-remédiation | Cette passe | Statut |
|---|:---:|:---:|:---:|
| **Documentation & Architecture** | 9,0 | **8,8 / 10** | 🟢 Exemplaire, un défaut de reproductibilité |
| **Sécurité & Cryptographie** | 8,8 | **8,5 / 10** | 🟢 Solide, un chemin de perte de secrets |
| **Qualité du Code & Architecture** | 8,7 | **8,3 / 10** | 🟢 Prêt pour l'entreprise, trois défauts nommés |
| **Conformité Réglementaire & Standards** | 9,2 | **9,2 / 10** | 🟢 Certifiable |
| **Global** | 8,9 | **8,7 / 10** | 🟢 |

**La note baisse, et c'est l'objet de la passe.** Rien n'a régressé : trois défauts qui étaient là depuis toujours sont désormais visibles. Un audit qui ne fait que reconfirmer ce que le précédent a mesuré mesure le précédent audit.

### Nouveaux constats

| # | Constat | Sévérité | Preuve |
|:--:|---|:--:|---|
| **A1** | L'étape secrets **avale un échec de Betterleaks** (`catch (Exception ignored) {}`) et présente les seuls résultats de Gitleaks comme une analyse complète. Selon la sémantique même d'ADR-0007, une liste non nulle est l'affirmation positive « a tourné et n'a rien trouvé », qui **résout** les anomalies de ce type. Une panne de Betterleaks peut donc résoudre silencieusement des fuites d'identifiants. | 🔴 **Élevée** | [ScanRunner.java:140](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java) |
| **A2** | La déduplication inter-scanners n'est **pas garantie**. `IssueFingerprint.of` inclut l'`identifier` propre au scanner (l'identifiant de règle), et les deux scanners de secrets exécutent des jeux de règles différents — un même identifiant fuité trouvé par les deux peut donc produire deux anomalies. | 🟠 **Moyenne** | [IssueFingerprint.java:77](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/issues/IssueFingerprint.java) |
| **A3** | Les diagrammes C4 committés ne sont **pas reproductibles** par le script documenté : exécuter `scripts/generate-c4-diagrams.sh` réécrit les six artefacts (364 lignes modifiées) et supprime trois fichiers `.puml` obsolètes suivis par git à la racine `c4/`. | 🟡 **Faible** | Vérifié en exécutant le script |

---

## 📚 2. Documentation & Architecture — 8,8

### 2.1 Modèle Bertrand Florat — vérifié complet et synchronisé

Les cinq vues autoportantes sont présentes dans les deux langues à **parité de lignes exacte** :

| Vue | EN | FR |
|---|:--:|:--:|
| Applicative | 88 | 88 |
| Sécurité | 75 | 75 |
| Dimensionnement | 52 | 52 |
| Infrastructure | 66 | 66 |
| Développement | 73 | 73 |

### 2.2 Modèle de menaces STRIDE — vérifié complet

Non pas affirmé d'après le sommaire du document, mais compté dans le texte : **entités E1–E4, processus P1–P5, magasins DS1–DS2 et les seize flux F1–F16**, avec les six catégories STRIDE traitées (Spoofing 3, Tampering 7, Repudiation 1, Information Disclosure 8, Denial of Service 2, Elevation of Privilege 6). [EN](../../architecture/security/en/STRIDE_THREAT_MODEL.en.md) et [FR](../../architecture/security/fr/STRIDE_THREAT_MODEL.fr.md) font 171 lignes chacun — parité exacte.

### 2.3 Modèle C4 — sain, mais les artefacts ne sont pas reproductibles (**A3**)

[`workspace.dsl`](../../architecture/c4/workspace.dsl) modélise cinq conteneurs sur trois niveaux avec `autoLayout`, et le modèle correspond au système tel que construit (UI Angular, control plane Spring, base, démon Docker, agent distant).

**Ce qui a été testé plutôt que lu.** Exécuter le script du dépôt lui-même,
[`scripts/generate-c4-diagrams.sh`](../../../scripts/generate-c4-diagrams.sh), réécrit chaque
artefact committé. La dérive est de **format, pas de modèle** — les fichiers committés viennent
d'un exporteur plus ancien émettant des blocs `<style>` avec des classes de stéréotype en base64,
tandis que la commande documentée produit des primitives `c4plantuml` `Person(...)`/`Rel(...)`. Le
contenu du modèle est équivalent.

Cela compte tout de même, pour la raison que ce projet applique ailleurs : un artefact qu'on ne
peut pas régénérer avec la commande qui prétend le générer n'est pas de l'architecture-as-code,
c'est une image. Et un script qui produit un diff de 364 lignes à chaque exécution est un script
qu'on cesse d'exécuter. Les trois `.puml` suivis à la racine `c4/` étaient des doublons obsolètes
d'une disposition antérieure ; le script les supprime, et c'est ainsi qu'ils ont été trouvés.

**Régénérés dans ce commit**, de sorte que la commande documentée et l'état committé s'accordent
désormais.

### 2.4 ADR et parité bilingue — vérifiés

Treize ADR dans les deux arbres, chaîne de remplacement intacte (0011 → 0013). Liens de
documentation : **331 liens relatifs, 0 cassé**, défendus par le job de CI `docs`. La parité du
corpus opérationnel tient à 0–2 % sur les trois documents réconciliés ; `GETTING_STARTED.fr` reste
11 % plus court sur une divergence structurelle.

---

## 🛡️ 3. Sécurité & Cryptographie — 8,5

### 3.1 Contrôles vérifiés

| Contrôle | État |
|---|---|
| Limitation de débit (`LoginRateLimitFilter`, Bucket4j) | ✅ Token-bucket en amont d'Argon2id ; `X-Forwarded-For` honoré uniquement derrière un proxy de confiance configuré ; LRU bornée élaguée à l'insertion |
| Argon2id, MFA TOTP | ✅ MFA joignable et tentatives plafonnées (3 par défi, détruit au dernier échec) ; les deux vérifiés par mutation |
| SCIM 2.0 | ✅ `/scim/v2/Users` et `/scim/v2/Groups`, `@RequiresAdministrator`, `application/scim+json` |
| Synchronisation de groupes OIDC | ✅ Claim `groups` associé à l'appartenance d'équipe ([OidcConfiguration.java:164](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/security/OidcConfiguration.java)) |
| AES-256-GCM au repos, KMS Vault | ✅ Contexte lié à la ligne ; `kms-type=vault` refuse désormais de démarrer sans point de terminaison joignable |
| Bac à sable des scanners | ✅ `cap_drop: ALL`, `no-new-privileges`, `network: none` par défaut, épinglé par digest, **rootfs en lecture seule** avec tmpfs `noexec`, aucune socket Docker |
| Isolation de l'agent | ✅ Imposée par le graphe de modules, réaffirmée par `AgentIsolationTest` |
| Chaîne d'audit SHA-256 | ✅ Chaînée, avec ses limites désormais énoncées dans le document de conformité (§5.1) |
| Quatre-yeux | ✅ Identités distinctes, vérifié par mutation |

### 3.2 A1 — l'étape secrets est le seul endroit où ADR-0007 n'est pas appliqué 🔴

Tous les autres scanners renvoient `Optional<List<…>>` et passent par `ran(…)`, qui lève quand
l'analyse n'a pas eu lieu, de sorte que l'étape inscrit un échec et laisse l'artefact `null`.
L'étape secrets, non :

```java
List<SecretsScanner.SecretFinding> allSecrets = new ArrayList<>(secrets.scan(workspace, subPath));
try {
    allSecrets.addAll(betterleaks.scan(workspace, subPath));
} catch (Exception ignored) {
}
artifacts.secrets(allSecrets);
```

`BetterleaksScanner.scan` signale **pourtant** l'échec correctement — il lève
`ScannerFailureException.exited(...)` sur un code de sortie mauvais. L'appelant le jette.

**Pourquoi c'est le pire endroit possible.** ADR-0007 énonce que `[]` est l'affirmation positive
*« l'étape a tourné et n'a rien trouvé »*, qui **résout** les anomalies ouvertes de ce type, tandis
que `null` signifie « n'a pas tourné » et laisse le backlog intact. Ici, un échec de Betterleaks
produit une liste non nulle — les seuls résultats de Gitleaks — donc l'étape affirme une analyse
de secrets complète. Tout identifiant fuité que seul Betterleaks détecte est résolu, silencieusement,
sans la moindre erreur nulle part. Le type de constat est la fuite d'identifiants, où une fausse
résolution est la plus coûteuse que le produit puisse produire.

Aucun des deux scanners ne renvoie d'`Optional` : l'étape n'a donc aucun moyen d'exprimer « n'a pas
tourné », même si l'exception n'était pas avalée.

**Recommandation :** faire renvoyer `Optional<List<…>>` aux deux scanners de secrets et les router
par `ran(…)` comme toutes les autres étapes, en ne fusionnant que si les deux ont réussi. Si un
mode dégradé est souhaité, il doit être explicite — inscrire la couverture partielle sur l'analyse
plutôt que de déduire la complétude d'une liste non nulle.

### 3.3 Ce qui retient le reste

Le miroir d'audit reste désactivé par défaut : le cas de la feuille supprimée est donc ouvert sur
une installation par défaut — désormais visible dans le score de conformité au lieu d'être
silencieux. La MFA n'a toujours pas de couverture de bout en bout.

---

## ⚙️ 4. Qualité du Code & Architecture Logicielle — 8,3

### 4.1 Forces vérifiées

**Spring Boot 4.1.0 / JDK 25**, 177 classes de test unitaire, 7 classes d'intégration, **zéro
`TODO`/`FIXME`** dans les sources de production. ArchUnit impose six règles dont la garde d'import
vide. La couverture est mesurée et défendue : **83,6 % instructions / 69,4 % branches** sur
`common.domain` face à un plancher 80/65 rattaché à `check`. Flyway porte 14 migrations natives par
dialecte sur quatre moteurs, `ddl-auto: validate`, avec `SchemaParityIntegrationTest` qui demande à
chaque moteur si entités et schéma s'accordent — et `nightly.yml` exécute désormais les quatre.

**ADR-0007 est implémenté** dans sept scanners via `ran(…)` — partout sauf au §3.2.

### 4.2 A2 — la promesse de déduplication est plus étroite qu'annoncé 🟠

`IssueFingerprint.of` hache la cible, le type, l'**identifier**, le purl-ou-paquet et le chemin de
fichier. L'`identifier` est *l'identifiant de règle propre au scanner*.

Gitleaks et Betterleaks partagent une image épinglée mais exécutent des **configurations de règles
différentes**. Deux jeux de règles nommant différemment le même secret produisent deux
identifiants, donc deux empreintes, donc **deux anomalies pour un seul identifiant fuité** — avec
`times_seen`, triage et état VEX suivis séparément sur chacune.

La déduplication est réelle *au sein* d'un scanner et d'une analyse à l'autre ; *entre* scanners
elle ne tient que si les identifiants de règle coïncident. Aucun test ne couvre le cas
inter-scanners : `IssueFingerprintTest` existe, mais rien n'exerce un secret rapporté par les deux
outils.

**Recommandation :** trancher l'intention explicitement. Soit normaliser les identifiants de
secrets vers un vocabulaire commun avant l'empreinte, soit retirer l'`identifier` de l'empreinte
des secrets au profit du chemin de fichier plus une empreinte de la valeur détectée. Puis le
tester — la promesse figure dans la documentation du produit.

### 4.3 Reportés de la passe précédente

| # | Constat | Note |
|:--:|---|---|
| **N1** | `/api/v1/compliance/summary` émet neuf requêtes de comptage par cible plus un balayage non borné de la table d'audit. | La règle que `TriageEvents.findForIssues` énonce dans son propre commentaire, rompue dans le service qui produit le rapport d'un auditeur. |
| **R1** | `nightly.yml` n'a jamais été exécuté. | Déclencher une fois en `workflow_dispatch` avant que sa pastille verte ne signifie quelque chose. |
| **R2** | Aucune couverture MFA de bout en bout. | `auth.spec.ts` n'a toujours aucun cas MFA. |

---

## 📋 5. Conformité Réglementaire & Standards — 9,2

**Moteurs réglementaires vérifiés présents et évalués dans le domaine pur :** NIS 2 (art. 21), CRA
UE (art. 10–11), DORA (art. 9/11/13/16), ISO/IEC 27001, PCI-DSS v4.0 et OWASP — six référentiels,
scorés par `ComplianceEngine` sans dépendance à une base, une horloge ou un framework, donc
exhaustivement testables.

**Interopérabilité de la chaîne d'approvisionnement vérifiée par inventaire de classes :**
CycloneDX (1.6), SPDX (2.3), CSAF 2.0, OpenVEX, EPSS et reachability disposent tous de packages de
domaine dédiés et de tests de routes.

**La propriété différenciante, confirmée.** Le moteur mesure désormais le control plane et pas
seulement la flotte : un contrôle est plafonné à `PARTIAL` quand la capacité qui le porte est
éteinte (pas de clé → 60, pas de miroir d'audit → 70, quatre-yeux désactivé → 75), et le plafond ne
fait jamais que baisser. Le §5.1 du document de conformité énonce ce que la chaîne d'audit prouve,
ce qu'elle ne prouve pas, et ce qui la ferme.

**Ce qui l'empêche de monter :** le cas de la feuille supprimée reste ouvert sur une installation
par défaut, et le A1 ci-dessus signifie qu'un score `SECRETS_MANAGEMENT` peut reposer sur une
analyse qui n'a silencieusement pas tourné entièrement — un chiffre de conformité appuyé sur un
constat qui s'est résolu tout seul.

---

## 🎯 6. Recommandations Priorisées

### 🔴 Avant la prochaine release
1. **Faire obéir l'étape secrets à ADR-0007** — les deux scanners renvoient `Optional`, routés par `ran(…)`, sans exception avalée. Une analyse de secrets partielle ne doit jamais se présenter comme complète *(A1, §3.2)*.

### 🟠 Ensuite
2. **Trancher l'intention de déduplication inter-scanners et la tester** *(A2, §4.2)*.
3. **Réduire le N+1 de conformité** à des requêtes groupées et borner la vérification de chaîne *(N1)*.
4. **Exécuter `nightly.yml` une fois à la main** et corriger ce qu'il révèle *(R1)*.
5. **Ajouter un cas MFA à `auth.spec.ts`** *(R2)*.

### 🟡 Plus tard
6. Ajouter la régénération C4 à la CI comme contrôle de dérive, pour que les artefacts ne puissent plus diverger en silence *(A3)*.
7. Amener `GETTING_STARTED.fr` à la parité de lignes, ou consigner la divergence structurelle.
8. Envisager un chemin de miroir par défaut pour les déploiements conteneurisés.

---

## 7. Conclusion

Les quatre axes tiennent bien à la vérification directe. Le modèle Florat, le modèle STRIDE et le
registre d'ADR sont complets, synchronisés et — fait peu commun — exacts sur leurs propres limites.
Les contrôles de sécurité sont câblés comme ils étaient conçus, et plusieurs sont défendus par des
tests dont on a montré qu'ils échouent quand on retire le correctif. Le moteur de conformité se
mesure lui-même, ce qui est assez rare pour être la propriété la plus distinctive du projet.

En face, cette passe est allée sur un terrain que les rapports précédents n'avaient pas couvert et
y a trouvé trois défauts réels, dont un sérieux : **la seule étape qui traite les identifiants
fuités est la seule où la règle du projet contre la perte silencieuse de données n'est pas
appliquée**, et un échec de scanner y résout des constats au lieu de signaler une panne. Le
correctif est petit — un `Optional` et un `catch` retiré — et c'est la seule chose de ce rapport qui
ne devrait pas attendre.

**8,7 / 10.** La note plus basse n'est pas une régression ; c'est ce qui arrive quand un audit cesse
de relire ses propres conclusions et va regarder ailleurs.
