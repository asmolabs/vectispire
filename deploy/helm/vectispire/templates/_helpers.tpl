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
{{- if not .Values.agents.token.secretName -}}
{{- fail "agents.token.secretName is required: the agent's API key, scope agent." -}}
{{- end -}}
{{- if not (has .Values.agents.dind.variant (list "privileged" "rootless")) -}}
{{- fail (printf "agents.dind.variant is privileged or rootless, not %q." .Values.agents.dind.variant) -}}
{{- end -}}
{{- if and (eq .Values.agents.dind.variant "rootless") (not .Values.agents.dind.rootless.acknowledgeUnreadableWorkspaces) -}}
{{- fail "agents.dind.variant rootless does not scan with this release's agent: under docker:dind-rootless the workspace the agent owns as uid 1000 reads as root's to a scanner run as uid 1000, and every scanner is absent (decision 0038). Set agents.dind.rootless.acknowledgeUnreadableWorkspaces to render it anyway." -}}
{{- end -}}
{{- end -}}
{{- end -}}
