# Security Architecture & STRIDE Threat Model / Modélisation des Menaces STRIDE

Ce répertoire rassemble l'analyse formelle de sécurité et la modélisation des menaces selon la méthodologie **STRIDE** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) pour le plan de contrôle Vectispire et ses composants d'analyse.

---

### 📚 Documentation disponible :

- 🇫🇷 **[Modélisation des Menaces STRIDE (Français)](fr/STRIDE_THREAT_MODEL.fr.md)**
- 🇬🇧 **[STRIDE Threat Model (English)](en/STRIDE_THREAT_MODEL.en.md)**

---

### 🛡️ Synthèse des Frontières de Sécurité

1. **Isolation des Conteneurs de Scan** : `cap_drop: ALL`, `read-only`, `no-new-privileges`, réseau coupé (`network: none` sauf Grype).
2. **Isolation des Agents Distants** : Communication HTTP Long-Polling exclusive, aucun accès JDBC, aucune possession de `ENCRYPTION_KEY`.
3. **Protection des Données au Repos** : Chiffrement AES-256-GCM des clés SSH privées et secrets d'intégration.
4. **Infalsificabilité du Journal d'Audit** : Scellement cryptographique par chaîne de hachage SHA-256.
