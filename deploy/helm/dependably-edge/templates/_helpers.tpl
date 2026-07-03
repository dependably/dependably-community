{{/* Common name and label helpers. */}}
{{- define "dependably-edge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "dependably-edge.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "dependably-edge.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "dependably-edge.labels" -}}
app.kubernetes.io/name: {{ include "dependably-edge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "dependably-edge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dependably-edge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
