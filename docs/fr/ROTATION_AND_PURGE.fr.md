# Rotation des Secrets & Purge d'Historique

Ce document récapitule les procédures de rotation des clés et de purge des secrets.

---

## 1. Procédures de Rotation des Secrets

### 1.1 Clés Déploiement SSH
Lors de la rotation d'une clé SSH privée de déploiement :
1. **Révoquer** l'ancienne clé publique sur le fournisseur Git (GitHub / GitLab).
2. **Générer** une nouvelle paire de clés Ed25519 :
   ```bash
   ssh-keygen -t ed25519 -C "vectispire-deploy" -f ~/vectispire-deploy
   ```
3. **Mettre à jour** la clé dans Vectispire via la page `/ssh-keys`. Vectispire chiffre automatiquement la clé avec AES-256-GCM et lie le ciphertext à la ligne (`ssh_key:<id>:private_key`).
4. **Supprimer** l'ancienne entrée obsolète.

### 1.2 Rotation de la Clé Principale (`ENCRYPTION_KEY`)
1. Générer une nouvelle clé AES 256 bits :
   ```bash
   openssl rand -base64 32
   ```
2. Configurer la nouvelle clé dans `ENCRYPTION_KEY` et placer l'ancienne clé dans `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` pour permettre la transition et le ré-encodage fluide.

### 1.3 Mots de Passe Utilisateurs
Pour forcer le changement de mot de passe à la prochaine connexion d'un utilisateur :
```sql
UPDATE t_user SET must_change_password = 1 WHERE username = 'admin';
```

---

## 2. Purge des Données Sensibles & Rétention

- **Payloads Bruts des Scanners (Gitleaks, etc.)** : Les rapports bruts contenant potentiellement des secrets en clair sont automatiquement purgés par le service de rétention (`RetentionService`).
- **Journal d'Audit** : Les entrées d'audit sont scellées cryptographiquement par chaîne de hash (`AuditChain`) et ne sont jamais modifiées.
