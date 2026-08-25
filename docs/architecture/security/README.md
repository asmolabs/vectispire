# Security architecture & STRIDE threat model / Architecture de sécurité & modèle de menaces STRIDE

The formal threat analysis for the control plane and its analysis components, one pass per STRIDE
category — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation
of Privilege — each paired with the control that answers it.

L'analyse formelle des menaces pour le plan de contrôle et ses composants d'analyse, une passe par
catégorie STRIDE — usurpation, altération, répudiation, divulgation, déni de service, élévation de
privilège — chacune associée au contrôle qui y répond.

- **[STRIDE threat model (English)](en/STRIDE_THREAT_MODEL.en.md)**
- **[Modélisation des menaces STRIDE (Français)](fr/STRIDE_THREAT_MODEL.fr.md)**

The narrative summary is [03 — Security](../en/03-security.md) ·
[03 — Sécurité](../fr/03-security.md): that page gives the shape of the problem, these give the
enumeration.

---

## The four boundaries, in one paragraph each / Les quatre frontières, en un paragraphe chacune

**Scan container isolation.** `cap_drop: ALL`, a read-only root filesystem, `no-new-privileges`,
and the network cut off except where a tool must fetch its database. The code being analysed is
hostile by assumption.

**Isolation des conteneurs d'analyse.** `cap_drop: ALL`, une racine en lecture seule,
`no-new-privileges`, et le réseau coupé sauf là où un outil doit récupérer sa base. Le code analysé
est hostile par hypothèse.

**Remote agent isolation.** HTTP long polling only: an agent opens no JDBC connection and never
holds `ENCRYPTION_KEY`. It is given scoped credentials and sealed material per scan.

**Isolation des agents distants.** Long polling HTTP uniquement : un agent n'ouvre aucune connexion
JDBC et ne détient jamais `ENCRYPTION_KEY`. Il reçoit des identifiants restreints et du matériel
scellé par analyse.

**Data at rest.** AES-256-GCM over private SSH keys and integration secrets, under a key the
process is given and never stores.

**Données au repos.** AES-256-GCM sur les clés SSH privées et les secrets d'intégration, sous une
clé que le processus reçoit et ne stocke jamais.

**Audit log integrity.** A SHA-256 hash chain, mirrored to a second medium — the chain alone
cannot see the deletion of its own last entry.

**Intégrité du journal d'audit.** Une chaîne de hachage SHA-256, doublée d'un miroir sur un second
médium — la chaîne seule ne peut pas voir la suppression de sa propre dernière entrée.
