# Architecture

## Control Flow

1. Operator watches Ingress resources and `DoMonitor` custom resources.
2. Desired monitor configuration is derived from annotations or CRD spec.
3. Operator reconciles DigitalOcean Uptime checks and alerts using the API.
4. Operator updates and cleans up remote resources when Kubernetes state changes.

## Source of Truth

- Kubernetes resources are the source of truth.
- The operator continuously converges DigitalOcean monitoring resources to match cluster state.

## Components

- `domonitor_operator/domonitor_operator.py`: reconciliation and event handling.
- `domonitor_operator/digitalocean.py`: DigitalOcean API integration.
- `manifests/` and `charts/`: deployment and CRD packaging.
