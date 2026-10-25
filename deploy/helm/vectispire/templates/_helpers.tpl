{{- define "vectispire.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "vectispire.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "vectispire.selector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: control-plane
{{- end -}}

{{- define "vectispire.agentSelector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end -}}

{{/* An image by digest, refused without one: a tag can be moved under a running release. */}}
{{- define "vectispire.image" -}}
{{- if not .digest -}}
{{- fail (printf "%s has no digest: the chart deploys images by digest only." .repository) -}}
{{- end -}}
{{- printf "%s:%s@%s" .repository .tag .digest -}}
{{- end -}}

{{- define "vectispire.agentNamespace" -}}
{{- default .Release.Namespace .Values.agents.namespace -}}
{{- end -}}

{{/*
What the chart refuses to render, each with the reason an operator reads at `helm install` rather than
in a pod's log.
*/}}
{{- define "vectispire.validate" -}}
{{- if not .Values.database.url -}}
{{- fail "database.url is required: the chart deploys no database (decision 0038 §4)." -}}
{{- end -}}
{{- if not (hasPrefix "jdbc:" .Values.database.url) -}}
{{- fail "database.url is a JDBC URL — jdbc:mysql://db.example.org:3306/vectispire." -}}
{{- end -}}
{{- if not .Values.database.password.secretName -}}
{{- fail "database.password.secretName is required." -}}
{{- end -}}
{{- if not .Values.secrets.encryptionKey.secretName -}}
{{- fail "secrets.encryptionKey.secretName is required: without the key no secret can be saved, and with another one none can be read." -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.trustedProxies) -}}
{{- fail "trustedProxies is required with an Ingress: the ingress controller's addresses or CIDR. Empty, every audit entry and rate limit names the controller, and X-Forwarded-Proto is ignored." -}}
{{- end -}}
{{- if and .Values.trustedProxies (not .Values.networkPolicy.enabled) (not .Values.trustedProxiesWithoutNetworkPolicy) -}}
{{- fail "trustedProxies needs networkPolicy.enabled: without it any pod in the cluster reaches port 3180 directly, and a peer in that range is believed about the client's address. Set trustedProxiesWithoutNetworkPolicy only where the range holds the ingress controller and nothing else." -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.tls.secretName) (not .Values.ingress.allowPlainHttp) -}}
{{- fail "ingress.tls.secretName is required: the interface signs people in. Set ingress.allowPlainHttp only for TLS ending before the Ingress." -}}
{{- end -}}
{{- if and (gt (int .Values.replicaCount) 1) .Values.auditMirror.enabled (ne .Values.auditMirror.accessMode "ReadWriteMany") -}}
{{- fail "replicaCount above 1 with the audit mirror needs auditMirror.accessMode ReadWriteMany: each pod writes its own file on the shared volume." -}}
{{- end -}}
{{- if and .Values.publicUrl (not (regexMatch "^https?://[^/?#]+" .Values.publicUrl)) -}}
{{- fail "publicUrl is an address people open: https://vectispire.example.org. It goes into the links of every reminder, ticket and exported document." -}}
{{- end -}}
{{- if .Values.mail.host -}}
{{- if regexMatch "[:/\\s]" .Values.mail.host -}}
{{- fail "mail.host is the relay's name alone, without a scheme or a port: the port is mail.port." -}}
{{- end -}}
{{- if not .Values.mail.from -}}
{{- fail "mail.from is required with mail.host: unset, the application signs as vectispire@localhost, which a relay refuses." -}}
{{- end -}}
{{- if and .Values.mail.username (not .Values.secrets.mailPassword.secretName) -}}
{{- fail "mail.username needs secrets.mailPassword.secretName: the relay would be asked to authenticate with an empty password. Leave mail.username empty for an anonymous relay." -}}
{{- end -}}
{{- else if or .Values.mail.username .Values.secrets.mailPassword.secretName -}}
{{- fail "mail.username or secrets.mailPassword is set without mail.host: no relay is configured, so nothing would be sent. Set mail.host, or remove them." -}}
{{- end -}}
{{- if .Values.agents.enabled -}}
{{- if not .Values.agents.controlPlaneUrl -}}
{{- fail "agents.controlPlaneUrl is required: the control plane as the agent reaches it, through the Ingress over HTTPS." -}}
{{- end -}}
{{- if not (hasPrefix "https://" (lower .Values.agents.controlPlaneUrl)) -}}
{{- fail "agents.controlPlaneUrl must be https://: the agent sends its key on every poll, and receives deployment keys and forge tokens sealed for it." -}}
{{- end -}}
{{- if not (has .Values.agents.executor (list "dind" "kubernetes")) -}}
{{- fail (printf "agents.executor is dind or kubernetes, not %q." .Values.agents.executor) -}}
{{- end -}}
{{- if eq .Values.agents.executor "kubernetes" -}}
{{- $scans := include "vectispire.scansNamespace" . -}}
{{- if not $scans -}}
{{- fail "agents.kubernetes.scansNamespace is required with the Kubernetes executor: the namespace its scan pods run in, under Pod Security restricted." -}}
{{- end -}}
{{- if or (eq $scans (include "vectispire.agentNamespace" .)) (eq $scans .Release.Namespace) -}}
{{- fail "agents.kubernetes.scansNamespace must be a namespace of its own: the agent's Role creates, execs into and deletes every pod there, and would reach the agent's own pod or the control plane's." -}}
{{- end -}}
{{- if and .Values.agents.networkPolicy.enabled (not .Values.agents.kubernetes.apiServer.cidrs) -}}
{{- fail "agents.kubernetes.apiServer.cidrs is required with the Kubernetes executor and the network policy: the agent calls the API server, whose address excludeCidrs usually covers. List its endpoints (kubectl get endpoints kubernetes -n default)." -}}
{{- end -}}
{{- end -}}
{{- $nodeAffinity := dig "nodeAffinity" "requiredDuringSchedulingIgnoredDuringExecution" dict (.Values.agents.affinity | default dict) -}}
{{- if and (not .Values.agents.acknowledgeSharedNodes) (or (not (or .Values.agents.nodeSelector $nodeAffinity)) (not .Values.agents.tolerations)) -}}
{{- fail "agents.nodeSelector (or a required agents.affinity.nodeAffinity) and agents.tolerations are required: the agent's scanners get nodes of their own — with dind its Docker daemon runs privileged, root on its node; with the Kubernetes executor its scan pods read hostile trees and their PID limit is the pool's kubelet setting (decision 0045 §6) — selected, and tainted so that nothing else lands there. Set agents.acknowledgeSharedNodes to render it on shared nodes anyway." -}}
{{- end -}}
{{- if not .Values.agents.token.secretName -}}
{{- fail "agents.token.secretName is required: the agent's API key, scope agent." -}}
{{- end -}}
{{- if not .Values.agents.signingKey.secretName -}}
{{- fail "agents.signingKey.secretName is required: without a pinned signing key the control plane accepts the agent's results unattested." -}}
{{- end -}}
{{- if and (not .Values.agents.networkPolicy.enabled) (not .Values.agents.networkPolicy.acknowledgeClusterReachable) -}}
{{- fail "agents.networkPolicy.enabled is false: the agents' pods would have no egress rule at all, and a scanner escaping its container would reach every pod, the nodes, the database and the cloud metadata endpoint. Keep the policy and list agents.networkPolicy.excludeCidrs, or set agents.networkPolicy.acknowledgeClusterReachable to render it without one." -}}
{{- end -}}
{{- if and .Values.agents.networkPolicy.enabled (not .Values.agents.networkPolicy.excludeCidrs) (not .Values.agents.networkPolicy.acknowledgeClusterReachable) -}}
{{- fail "agents.networkPolicy.excludeCidrs is required: a scanner's traffic leaves through the agent's pod, and with nothing excluded it reaches the whole cluster. List the pod, service and node ranges and the database's subnet, or set agents.networkPolicy.acknowledgeClusterReachable." -}}
{{- end -}}
{{- range $i, $to := .Values.agents.networkPolicy.allowTo -}}
{{- if not (or $to.ipBlock $to.namespaceSelector $to.podSelector) -}}
{{- fail (printf "agents.networkPolicy.allowTo[%d] names no destination: give it an ipBlock, a namespaceSelector or a podSelector. A rule to no one in particular is its ports everywhere, past excludeCidrs." $i) -}}
{{- end -}}
{{- if not $to.ports -}}
{{- fail (printf "agents.networkPolicy.allowTo[%d] has no ports, and would open every port of what it selects. Add the ones it is for: ports: [{port: 443}] for the ingress controller, 443 or 22 for a Git host or a registry (protocol defaults to TCP)." $i) -}}
{{- end -}}
{{- range $to.ports -}}
{{- if not .port -}}
{{- fail (printf "agents.networkPolicy.allowTo[%d].ports has an entry without a port, which opens every port of its protocol. Name it: {port: 443}." $i) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.agents.executor "dind" -}}
{{- if not (has .Values.agents.dind.variant (list "privileged" "rootless")) -}}
{{- fail (printf "agents.dind.variant is privileged or rootless, not %q." .Values.agents.dind.variant) -}}
{{- end -}}
{{- if and (eq .Values.agents.dind.variant "rootless") (not .Values.agents.dind.rootless.acknowledgeUnreadableWorkspaces) -}}
{{- fail "agents.dind.variant rootless does not scan with this release's agent: under docker:dind-rootless the workspace the agent owns as uid 1000 reads as root's to a scanner run as uid 1000, and every scanner is absent (decision 0038). Set agents.dind.rootless.acknowledgeUnreadableWorkspaces to render it anyway." -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}


{{/*
The address people reach Vectispire at: `publicUrl`, else `https://<ingress.host>` while the Ingress is on.
Https in both shapes the chart renders — TLS ends at the Ingress, or before it with `allowPlainHttp` — and
empty without an Ingress, where the chart cannot know the address.
*/}}
{{- define "vectispire.publicUrl" -}}
{{- if .Values.publicUrl -}}
{{- trimSuffix "/" .Values.publicUrl -}}
{{- else if and .Values.ingress.enabled .Values.ingress.host -}}
{{- printf "https://%s" .Values.ingress.host -}}
{{- end -}}
{{- end -}}

{{/*
The control plane's affinity: the operator's, plus a required anti-affinity to every agent pod. Their
docker:dind is privileged, root on its node, and this pod holds ENCRYPTION_KEY, which decrypts every
deployment key and forge token (decisions 0003, 0038). Kept apart in both directions: the scheduler honours
a running pod's required anti-affinity for pods arriving after it.

**Any agent, in any namespace, of any release** — matched on the `vectispire.dev/dind` label every agent pod
carries, under an empty namespaceSelector. More agents are more releases, often installed apart from the
control plane's, and a term naming this release and its agent namespace kept the control plane off its own
agents' nodes and none of the others' (the audit of 10 October 2026). Always rendered: a release without
agents is the one whose agents live in another.

**And off the Kubernetes executor's scan pods** (decision 0045), matched on the `vectispire.dev/agent` label each
carries: they run scanners on hostile trees, and a node is what an escape from one reaches. Two terms, both
required: a node holding either is refused.
*/}}
{{- define "vectispire.controlPlaneAffinity" -}}
{{- $affinity := deepCopy (.Values.affinity | default dict) -}}
{{- $anti := get $affinity "podAntiAffinity" | default dict -}}
{{- $required := get $anti "requiredDuringSchedulingIgnoredDuringExecution" | default list -}}
{{- $agents := dict "matchExpressions" (list (dict "key" "vectispire.dev/dind" "operator" "Exists")) -}}
{{- $term := dict "labelSelector" $agents "namespaceSelector" dict "topologyKey" "kubernetes.io/hostname" -}}
{{- $scanPods := dict "matchExpressions" (list (dict "key" "vectispire.dev/agent" "operator" "Exists")) -}}
{{- $scanTerm := dict "labelSelector" $scanPods "namespaceSelector" dict "topologyKey" "kubernetes.io/hostname" -}}
{{- $_ := set $anti "requiredDuringSchedulingIgnoredDuringExecution" (concat $required (list $term $scanTerm)) -}}
{{- $_ := set $affinity "podAntiAffinity" $anti -}}
{{- if $affinity -}}
{{- toYaml $affinity -}}
{{- end -}}
{{- end -}}

{{/*
Where a scanner's traffic may go: DNS, and everything outside the excluded ranges and the cloud metadata
addresses, plus each allowTo entry to its own ports. The agents' pods (their daemon's scanners leave through
them) and the Kubernetes executor's online scan pods (decision 0045) get the same rules.
*/}}
{{- define "vectispire.scannerEgress" -}}
# DNS to anything on port 53 unless `dnsTo` names the resolvers: the chart cannot know them — kube-dns,
# a node-local cache on a link-local address, another distribution's own — and a guess that misses
# leaves every agent unable to resolve the control plane.
- ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
  {{- with .Values.agents.networkPolicy.dnsTo }}
  to:
    {{- toYaml . | nindent 4 }}
  {{- end }}
# The scanners' traffic leaves through this pod too — the daemon's bridge is behind the pod's
# address — so this is what an escaped scanner can reach. The cluster's own ranges belong in
# excludeCidrs; the cloud metadata addresses are excluded whatever they say — link-local, and those
# outside it that the control plane's guard refuses too: Alibaba's, Oracle's legacy one, Azure's
# WireServer. IPv6 egress is not allowed at all, AWS's fd00:ec2::254 with it.
# With the Kubernetes executor, the API server's addresses too, whatever excludeCidrs covers: a scan pod
# never reaches it, and the agent's own policy adds the one rule that lets the agent through.
- to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
          {{- $apiServer := ternary (.Values.agents.kubernetes.apiServer.cidrs | default list) list (eq .Values.agents.executor "kubernetes") }}
          {{- toYaml (concat (.Values.agents.networkPolicy.excludeCidrs | default list) (list "169.254.0.0/16" "100.100.100.200/32" "192.0.0.192/32" "168.63.129.16/32") $apiServer | uniq) | nindent 10 }}
# One rule per destination, each to the ports it names: a rule without `ports` opens every port of
# what it selects, and the destination here usually lies inside a range excluded above — the ingress
# controller's pods, which a LoadBalancer address becomes once kube-proxy has translated it. The
# entry is the peer, so a namespaceSelector and a podSelector in it are ANDed, never ORed.
{{- range .Values.agents.networkPolicy.allowTo }}
- to:
    - {{ toYaml (omit . "ports") | nindent 6 | trim }}
  ports:
    {{- range .ports }}
    - port: {{ .port }}
      protocol: {{ .protocol | default "TCP" }}
      {{- with .endPort }}
      endPort: {{ . }}
      {{- end }}
    {{- end }}
{{- end }}
{{- end -}}

{{- define "vectispire.scansNamespace" -}}
{{- .Values.agents.kubernetes.scansNamespace -}}
{{- end -}}

{{/* The scan pods' placement, as the agent reads it: the agents' own pool. */}}
{{- define "vectispire.scanPlacement" -}}
{{- $placement := dict -}}
{{- with .Values.agents.nodeSelector }}{{ $_ := set $placement "nodeSelector" . }}{{ end -}}
{{- with .Values.agents.tolerations }}{{ $_ := set $placement "tolerations" . }}{{ end -}}
{{- with .Values.agents.affinity }}{{ $_ := set $placement "affinity" . }}{{ end -}}
{{- toJson $placement -}}
{{- end -}}
