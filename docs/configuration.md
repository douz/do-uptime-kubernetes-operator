# Configuration

## Ingress Annotations

- `douz.io/do-monitor`: set to `"true"` to enable monitoring for an Ingress.
- `douz.io/do-monitor-email`: verified email for alerts.
- `douz.io/do-monitor-slack-webhook`: Slack webhook URL.
- `douz.io/do-monitor-slack-channel`: Slack channel (for example `#alerts`).
- `douz.io/do-monitor-latency-threshold`: latency threshold in milliseconds.
- `douz.io/do-monitor-latency-period`: latency period window (for example `2m`).
- `douz.io/do-monitor-ssl-expiry`: days before certificate expiry to alert.

At least one alert channel (email or Slack) must be configured.

## DoMonitor CRD

You can declare monitor intent directly through `DoMonitor` resources. See the example in the root `README.md` usage section.

## Helm Values

Refer to `charts/do-uptime-operator/values.yaml` and `charts/do-uptime-operator/README.md` for the latest configurable values.
