# Getting Started

## Prerequisites

- Kubernetes cluster
- Helm 3
- DigitalOcean API token with monitoring permissions

## Install with Helm

```bash
helm repo add do-uptime-operator https://charts.douz.io
helm repo update
helm upgrade --install do-uptime-operator do-uptime-operator/do-uptime-operator \
  --namespace kube-system \
  --create-namespace \
  --set digitalocean.createSecret=true \
  --set digitalocean.token='<DIGITALOCEAN_TOKEN>'
```

## Verify Installation

```bash
kubectl -n kube-system get deployment do-monitor-operator
kubectl -n kube-system logs deployment/do-monitor-operator --tail=200
```
