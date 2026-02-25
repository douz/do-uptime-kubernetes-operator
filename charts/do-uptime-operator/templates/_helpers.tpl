{{- define "do-uptime-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "do-uptime-operator.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "do-uptime-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "do-uptime-operator.labels" -}}
helm.sh/chart: {{ include "do-uptime-operator.chart" . }}
app.kubernetes.io/name: {{ include "do-uptime-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "do-uptime-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "do-uptime-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "do-uptime-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "do-uptime-operator.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "do-uptime-operator.secretName" -}}
{{- if .Values.digitalocean.createSecret -}}
{{- printf "%s-token" (include "do-uptime-operator.fullname" .) -}}
{{- else -}}
{{- .Values.digitalocean.existingSecret -}}
{{- end -}}
{{- end -}}
