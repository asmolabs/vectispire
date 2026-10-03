# Vectispire Helm chart

The control plane on Kubernetes, as [decision 0038](../../../docs/architecture/en/decisions/0038-deploying-on-kubernetes.md)
lays it out. The installation guide's [Kubernetes section](../../../docs-site/getting-started/installation.md#kubernetes)
is the walkthrough. This file is the chart's reference.

## What it deploys

- **The control plane**, a Deployment pinned by digest, one replica, `strategy: Recreate`, the built-in
  worker off. It serves the interface from the same jar, behind a Service and an Ingress.
- **The audit mirror's volume**, one file per pod, kept by an uninstall (`helm.sh/resource-policy: keep`).
- **Optional:** NetworkPolicies, and scan agents in pods with a Docker-in-Docker sidecar (`agents.enabled`).

What it does not deploy:

- **The database**: point `database.url` at your MySQL.
- **The Secrets**: create them yourself, as shown below.
- **Agents on a Docker host outside the cluster**, which is where they are recommended to run.

**Report plugins answer 409 `report-executor-unavailable`** on this installation. The control plane has
no container endpoint, and report plugins need one (decision 0038, option D).

## Secrets

Each Secret reaches the pod as a file under `/run/secrets`, never as a variable. Create them yourself:

```bash
kubectl -n vectispire create secret generic vectispire-database \
  --from-literal=password="$(openssl rand -base64 24)"   # gitleaks:allow
kubectl -n vectispire create secret generic vectispire-keys \
  --from-literal=encryption-key="$(openssl rand -base64 32)" \
  --from-literal=bootstrap-password="$(openssl rand -base64 24)"   # gitleaks:allow
kubectl -n vectispire create secret tls vectispire-tls --cert=tls.crt --key=tls.key
```

| Value | Key (default) | Becomes |
|---|---|---|
| `secrets.encryptionKey` | `encryption-key` | `/run/secrets/encryption_key`, read through `ENCRYPTION_KEY_FILE`. **Back it up**: it decrypts every deployment key and token. |
| `database.password` | `password` | `/run/secrets/VECTISPIRE_DB_PASSWORD` |
| `secrets.bootstrapPassword` | `bootstrap-password` | the first administrator's password, read while no account exists |
| `secrets.signingKey` | `signing-key` | `vectispire.signing.key` — optional; set it with two replicas, and keep it |
| `secrets.oidcClientSecret` | `oidc-client-secret` | `vectispire.oidc.client-secret`, with `oidc.issuer` |
| `secrets.previousEncryptionKeys` | `previous-encryption-keys` | during a key rotation only |

## Required values

The chart refuses to render without these. Each refusal names its reason.

- `image.digest`
- `database.url` and `database.password.secretName`
- `secrets.encryptionKey.secretName`
- `trustedProxies` — the ingress controller's addresses or CIDR. Empty, every audit entry names the
  controller and TLS ending at the Ingress reads as plain HTTP.
- `ingress.tls.secretName`, unless `ingress.allowPlainHttp` is set
- with agents: `agents.controlPlaneUrl` and `agents.token.secretName`

See `values.example.yaml` for a complete installation.

## The database

MySQL, installed and backed up by you:

- **One host in the URL.** `mysql+srv` and several hosts are refused at startup.
- **TLS through Connector/J**: `sslMode=VERIFY_IDENTITY`. Put the server's CA in a PKCS12 truststore,
  set `database.trustStore` to its Secret, and name the truststore in the URL with
  `trustCertificateKeyStoreUrl=file:/etc/vectispire/mysql/truststore.p12`.
- **Server settings:** `max_allowed_packet` at least `160M`, and `default_time_zone` `'+00:00'`.
- Flyway migrates at startup under a MySQL named lock. **Back up before every upgrade**: there is no
  down migration.

## The Ingress

The default annotations are ingress-nginx's. Another controller needs the same three settings in its own
words:

- a read timeout of at least 60 s (agents long-poll for 30 s);
- a body size of at least 256 MB (agent results);
- TLS.

With `replicaCount: 2`:

- set `ingress.stickySessions`: single sign-on keeps its state in the servlet session;
- set `auditMirror.accessMode: ReadWriteMany`.

## Scan agents

**Outside the cluster (recommended).** The chart deploys nothing for this. Run the agent on a Docker
host, as the installation guide shows, with `VECTISPIRE_URL` set to the Ingress's HTTPS address.

**In the cluster (`agents.enabled: true`).** One pod per agent identity. Each pod has the agent and a
Docker daemon of its own:

- the daemon listens on a Unix socket in a shared `emptyDir`, never on TCP;
- the work directory is a second `emptyDir`, mounted at the same path in both containers.

- `agents.dind.variant: privileged` — `docker:dind` in a **privileged container, which is root on its
  node**. Give these pods:
  - a namespace of their own: created with Pod Security Admission's `privileged` level when
    `agents.createNamespace` is set;
  - nodes of their own: `agents.nodeSelector` and `agents.tolerations`, matching a tainted node pool;
  - the NetworkPolicy, with the cluster's pod and service ranges in `agents.networkPolicy.excludeCidrs`.

  Where privileged pods are forbidden, use a Docker host outside the cluster.
- `agents.dind.variant: rootless` — `docker:dind-rootless`. **It does not scan with this release's
  agent.** Under the rootless daemon's user namespace, a scanner running as uid 1000 sees the workspace
  the agent owns as uid 1000 as root's, and cannot read it. Every scanner is then absent from the scan.
  It also needs, on most clusters, either a privileged container or unconfined seccomp and AppArmor with
  an unmasked `/proc`. It renders only with `agents.dind.rootless.acknowledgeUnreadableWorkspaces: true`.

Create the agent on the **Agents** screen, then store its key:

```bash
kubectl -n vectispire-agents create secret generic vectispire-agent \
  --from-literal=token='<the key shown once>'   # gitleaks:allow
```

## Checking the chart

```bash
helm lint deploy/helm/vectispire -f deploy/helm/vectispire/ci/no-agents-values.yaml --strict
helm template vs deploy/helm/vectispire -f deploy/helm/vectispire/ci/dind-privileged-values.yaml
```

CI renders the three value sets under `ci/`: no agents, privileged DinD, and rootless DinD.
