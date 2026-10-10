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
{{- if .Values.agents.enabled -}}
{{- if not .Values.agents.controlPlaneUrl -}}
{{- fail "agents.controlPlaneUrl is required: the control plane as the agent reaches it, through the Ingress over HTTPS." -}}
{{- end -}}
{{- if not (hasPrefix "https://" (lower .Values.agents.controlPlaneUrl)) -}}
{{- fail "agents.controlPlaneUrl must be https://: the agent sends its key on every poll, and receives deployment keys and forge tokens sealed for it." -}}
{{- end -}}
{{- $nodeAffinity := dig "nodeAffinity" "requiredDuringSchedulingIgnoredDuringExecution" dict (.Values.agents.affinity | default dict) -}}
{{- if and (not .Values.agents.acknowledgeSharedNodes) (or (not (or .Values.agents.nodeSelector $nodeAffinity)) (not .Values.agents.tolerations)) -}}
{{- fail "agents.nodeSelector (or a required agents.affinity.nodeAffinity) and agents.tolerations are required: the agent's Docker daemon runs privileged, root on its node, so it gets nodes of its own — selected, and tainted so that nothing else lands there. Set agents.acknowledgeSharedNodes to render it on shared nodes anyway." -}}
{{- end -}}
{{- if not .Values.agents.token.secretName -}}
{{- fail "agents.token.secretName is required: the agent's API key, scope agent." -}}
{{- end -}}
{{- if not .Values.agents.signingKey.secretName -}}
{{- fail "agents.signingKey.secretName is required: without a pinned signing key the control plane accepts the agent's results unattested." -}}
{{- end -}}
{{- if and .Values.agents.networkPolicy.enabled (not .Values.agents.networkPolicy.excludeCidrs) (not .Values.agents.networkPolicy.acknowledgeClusterReachable) -}}
{{- fail "agents.networkPolicy.excludeCidrs is required: a scanner's traffic leaves through the agent's pod, and with nothing excluded it reaches the whole cluster. List the pod, service and node ranges and the database's subnet, or set agents.networkPolicy.acknowledgeClusterReachable." -}}
{{- end -}}
{{- if not (has .Values.agents.dind.variant (list "privileged" "rootless")) -}}
{{- fail (printf "agents.dind.variant is privileged or rootless, not %q." .Values.agents.dind.variant) -}}
{{- end -}}
{{- if and (eq .Values.agents.dind.variant "rootless") (not .Values.agents.dind.rootless.acknowledgeUnreadableWorkspaces) -}}
{{- fail "agents.dind.variant rootless does not scan with this release's agent: under docker:dind-rootless the workspace the agent owns as uid 1000 reads as root's to a scanner run as uid 1000, and every scanner is absent (decision 0038). Set agents.dind.rootless.acknowledgeUnreadableWorkspaces to render it anyway." -}}
{{- end -}}
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
*/}}
{{- define "vectispire.controlPlaneAffinity" -}}
{{- $affinity := deepCopy (.Values.affinity | default dict) -}}
{{- $anti := get $affinity "podAntiAffinity" | default dict -}}
{{- $required := get $anti "requiredDuringSchedulingIgnoredDuringExecution" | default list -}}
{{- $agents := dict "matchExpressions" (list (dict "key" "vectispire.dev/dind" "operator" "Exists")) -}}
{{- $term := dict "labelSelector" $agents "namespaceSelector" dict "topologyKey" "kubernetes.io/hostname" -}}
{{- $_ := set $anti "requiredDuringSchedulingIgnoredDuringExecution" (append $required $term) -}}
{{- $_ := set $affinity "podAntiAffinity" $anti -}}
{{- if $affinity -}}
{{- toYaml $affinity -}}
{{- end -}}
{{- end -}}
