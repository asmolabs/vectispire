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

**In one namespace.** Nothing the chart renders is cluster-wide: with agents off, every object lands in
the release's namespace, and an account that can only write there can install it. With agents in the
cluster, set `agents.namespace: ""` and `agents.createNamespace: false` to keep them in that namespace
too — see [Scan agents](#scan-agents).

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
  controller and TLS ending at the Ingress reads as plain HTTP. **With `networkPolicy.enabled`**: a peer
  in that range is believed about the client's address, so without a policy any pod calling port 3180
  directly could name any address — a fresh rate-limit bucket on every request, an audit entry naming
  somebody else. `trustedProxiesWithoutNetworkPolicy` renders it anyway, for a range holding the
  controller alone. The policy is enforced only by a CNI that enforces NetworkPolicy.
- `ingress.tls.secretName`, unless `ingress.allowPlainHttp` is set
- with agents: `agents.controlPlaneUrl`, over `https://` (the agent sends its key on every poll),
  `agents.token.secretName`, `agents.signingKey.secretName` (without a pinned key the agent's results are
  accepted unattested), `agents.networkPolicy.excludeCidrs`, `ports` on each
  `agents.networkPolicy.allowTo` entry, and `agents.nodeSelector` with `agents.tolerations` (below)

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

**Keep the client's address up to the controller.** `trustedProxies` believes the controller's
`X-Forwarded-For`, which is only what the controller saw; the application takes the rightmost address in
it that `trustedProxies` does not name. Behind a load balancer, with the controller's Service on
`externalTrafficPolicy: Cluster` (the default), a node translates the source (SNAT) and every client
arriving through it shares the node's address — one rate-limit bucket, audit entries and SIEM events
naming the node, or the controller when `trustedProxies` covers the nodes too. A load balancer that passes
packets through needs `externalTrafficPolicy: Local`; one that opens its own connection, the PROXY protocol
at both ends; an HTTP load balancer, the controller passing its `X-Forwarded-For` on (ingress-nginx's
`use-forwarded-headers` and `proxy-real-ip-cidr`) — only when it is the controller's sole way in, or a
client writes that header — with every proxy that appends its address named in `trustedProxies`. The
installation guide's [Ingress section](../../../docs-site/getting-started/installation.md#the-ingress)
details the three.

With `replicaCount: 2`:

- set `ingress.stickySessions`: single sign-on keeps its state in the servlet session;
- set `auditMirror.accessMode: ReadWriteMany`.

## The control plane's NetworkPolicy

`networkPolicy.enabled` keeps port 3180 to `networkPolicy.ingressFrom`, the ingress controller.
`networkPolicy.restrictEgress` also limits what the control plane reaches to DNS and the destinations
`networkPolicy.egress` lists — the database, the forges, the OIDC issuer, the SIEM collector, the trackers,
the threat-intelligence feeds.

**Leave the Kubernetes API server out of that list.** The application refuses the cluster's API service
and, on every address, ports 6443 and 10250 — the API server's usual port and the kubelet's — to every
setting that sends requests. It cannot refuse what it cannot name: kube-proxy translates the service to
the API server's real endpoints, node or control-plane addresses, and a managed cluster that publishes them
on 443 cannot be refused by port. Those addresses
(`kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes`) and the nodes' range are
the policy's to keep out. Without `restrictEgress` egress is open; the pod mounts no service-account token,
so a request that reaches the API server is anonymous.

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
    `agents.createNamespace` is set. In a single namespace you were given (`agents.namespace: ""`,
    `agents.createNamespace: false`), the chart creates nothing, and the pod is admitted only if that
    namespace's level is `privileged` — which also lets any other pod there run privileged. Check with
    `kubectl get namespace <ns> --show-labels`; a `restricted` or `baseline` level refuses it;
  - nodes of their own: `agents.nodeSelector` (or a required node affinity) and `agents.tolerations`,
    matching a tainted node pool. Without both the chart refuses to render
    (`agents.acknowledgeSharedNodes` overrides). Whatever you set, the chart gives the control plane a
    required anti-affinity to every agent pod — any release, any namespace, by the `vectispire.dev/dind`
    label: it holds `ENCRYPTION_KEY`, and never shares a node with a daemon that is root on it. On a
    single node the control plane stays Pending rather than share it;
  - the NetworkPolicy, with what an escaped scanner must not reach in `agents.networkPolicy.excludeCidrs`
    — the cluster's pod, service **and node** ranges, and the database's subnet when it is outside them.
    Empty, or the policy turned off (`agents.networkPolicy.enabled: false`), the chart refuses to render
    (`agents.networkPolicy.acknowledgeClusterReachable` overrides).
    `169.254.0.0/16`, the cloud metadata endpoint's range, and the metadata addresses outside it
    (`100.100.100.200`, `192.0.0.192`, `168.63.129.16`) are excluded whatever the list says.
  - **the ingress controller back, in `agents.networkPolicy.allowTo`, on port 443 only.** The agent
    reaches the control plane through the Ingress, and kube-proxy translates the Ingress's LoadBalancer
    address to a controller pod's before the policy applies — an address in the pod range you just
    excluded. Without an entry the agent never polls. An internal Git host or registry inside an excluded
    range is the same: an `ipBlock` with 443, 22 or both.

    ```yaml
    agents:
      networkPolicy:
        allowTo:
          - namespaceSelector:              # in the same entry: ANDed — these pods, in that namespace
              matchLabels:
                kubernetes.io/metadata.name: ingress-nginx
            podSelector:
              matchLabels:
                app.kubernetes.io/name: ingress-nginx
            ports:
              - port: 443                   # the pod's port, after translation; protocol defaults to TCP
    ```

    **An entry without `ports` is refused**, and so is a port without a number or an entry naming no
    peer. A NetworkPolicy rule without ports opens every port of what it selects: the controller's
    metrics and admission webhook, or every service of a Git host, to whatever escapes a scanner. The
    chart cannot tell an entry meant for all ports from one where they were forgotten, and forgetting is
    the likely case — so it asks rather than keeps the old reading. No shipped example had an entry; one
    written against the release candidate needs its `ports` added before `helm upgrade`. Each entry is a
    rule of its own, so one entry's ports never open another's peer.
  - DNS: port 53 to anywhere, unless `agents.networkPolicy.dnsTo` names your resolvers. The chart does
    not guess them — kube-dns by its labels misses NodeLocal DNSCache (a link-local address) and
    distributions that run their own, and a miss leaves the agent unable to resolve anything. Setting it
    keeps port 53 of every other pod and host out of a scanner's reach.

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

CI renders the four value sets under `ci/`: no agents, privileged DinD, rootless DinD, and a single
namespace with the agents beside the control plane. It checks that the first and the last render nothing
outside the release's namespace.

## At a release

`appVersion` and both images' `tag` and `digest` move together, once the release has pushed its images
(`docker buildx imagetools inspect ghcr.io/asmolabs/vectispire:<tag>`). CI fails a chart whose pinned tags
are not its `appVersion`; nothing can check the digests before the images exist, so this is a step of the
release, after the tag.
