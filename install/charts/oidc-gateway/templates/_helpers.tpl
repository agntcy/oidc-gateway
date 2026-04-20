{{/*
Copyright AGNTCY Contributors (https://github.com/agntcy)
SPDX-License-Identifier: Apache-2.0
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "oidc-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "oidc-gateway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "oidc-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "oidc-gateway.labels" -}}
helm.sh/chart: {{ include "oidc-gateway.chart" . }}
{{ include "oidc-gateway.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "oidc-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "oidc-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Envoy gateway labels
*/}}
{{- define "oidc-gateway.envoyLabels" -}}
{{ include "oidc-gateway.labels" . }}
app.kubernetes.io/component: envoy-gateway
{{- end }}

{{/*
Envoy gateway selector labels
*/}}
{{- define "oidc-gateway.envoySelector" -}}
{{ include "oidc-gateway.selectorLabels" . }}
app.kubernetes.io/component: envoy-gateway
{{- end }}

{{/*
AuthZ server labels
*/}}
{{- define "oidc-gateway.authzLabels" -}}
{{ include "oidc-gateway.labels" . }}
app.kubernetes.io/component: authz-server
{{- end }}

{{/*
AuthZ server selector labels
*/}}
{{- define "oidc-gateway.authzSelector" -}}
{{ include "oidc-gateway.selectorLabels" . }}
app.kubernetes.io/component: authz-server
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "oidc-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "oidc-gateway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Envoy service account name (for SPIFFE ID)
*/}}
{{- define "oidc-gateway.envoyServiceAccountName" -}}
{{- printf "%s-envoy-gateway" (include "oidc-gateway.fullname" .) }}
{{- end }}
