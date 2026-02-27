# DigitalOcean Uptime Monitor Operator

This Kubernetes Operator automates the creation, update, and deletion of [DigitalOcean Uptime Monitors](https://docs.digitalocean.com/products/monitoring/) and related alerts based on Ingress annotations. The Operator creates a Custom Resource of kind `DoMonitor`, which is the single source of truth and is in charge of creating DigitalOcean resources (monitors and alerts).

## Installation

1. **Add the public Helm repository**
   ```bash
   helm repo add do-uptime-operator https://douz.github.io/do-uptime-kubernetes-operator
   helm repo update
   ```

2. **Install with a new DigitalOcean token secret**
   ```bash
   helm upgrade --install do-uptime-operator do-uptime-operator/do-uptime-operator \
     --namespace kube-system \
     --create-namespace \
     --set digitalocean.createSecret=true \
     --set digitalocean.token='<DIGITALOCEAN_TOKEN>'
   ```

3. **Or install using an existing secret**
   ```bash
   helm upgrade --install do-uptime-operator do-uptime-operator/do-uptime-operator \
     --namespace kube-system \
     --create-namespace \
     --set digitalocean.createSecret=false \
     --set digitalocean.existingSecret=do-token-secret
   ```

### Operator Logs

If you need to troubleshoot or verify that the operator is running correctly, you can view its logs:

```bash
kubectl logs -f deployment/do-monitor-operator -f -n kube-system
```

## Usage

The `do-monitor-operator` will watch for Ingress resources with the `douz.io/do-monitor: "true"` annotation and create the Uptime Monitor and associated alerts accordingly. For example:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  namespace: default
  annotations:
    douz.io/do-monitor: "true"
    douz.io/do-monitor-email: "your-email@example.com"
    douz.io/do-monitor-slack-webhook: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    douz.io/do-monitor-slack-channel: "#your-slack-channel"
    douz.io/do-monitor-latency-threshold: "200"
    douz.io/do-monitor-latency-period: "2m"
    douz.io/do-monitor-ssl-expiry: "30"
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: example-service
                port:
                  number: 80
```

In this example, an Uptime Monitor (check) named `example-ingress-default-domonitor` (`<ingressName>-<namespace>-domonitor`) will be created, along with `down`, `latency`, and `sslExpiry` alerts, sending notifications to the specified email address and Slack channel.<br>

The same results can be achieved by creating a `DoMonitor` Resource as follows:

```yaml
---
apiVersion: douz.io/v1
kind: DoMonitor
metadata:
  name: ingress-test-default-domonitor
  namespace: default
spec:
  ingressName: ingress-test
  host: "example.com"
  config:
    email: "your-email@example.com"
    emailAlert: true
    slackWebhook: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    slackChannel: "#your-slack-channel"
    slackAlert: true
    latencyThreshold: 200
    latencyPeriod: "2m"
    sslExpiryPeriod: 30
```

### Ingress Annotations

- **`douz.io/do-monitor`:** Set to `"true"` to enable the Operator for an Ingress resource.
- **`douz.io/do-monitor-email`:** Email address to send alerts to (only verified emails in the DigitalOcean dashboard will work).
- **`douz.io/do-monitor-slack-webhook`:** Slack webhook URL for sending alerts to a channel.
- **`douz.io/do-monitor-slack-channel`:** Slack channel name (e.g., `#your-slack-channel`).
- **`douz.io/do-monitor-latency-threshold`:** Latency threshold in milliseconds.
- **`douz.io/do-monitor-latency-period`:** Period over which to measure latency (e.g., `"2m"`).
- **`douz.io/do-monitor-ssl-expiry`:** Number of days before SSL certificate expiry to trigger an alert.

At least one notification channel (email or Slack) must be provided.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests. Please follow the [DigitalOcean Uptime Monitor docs](https://docs.digitalocean.com/products/monitoring/) and [Kubernetes Operator patterns](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) when making changes.

### Running Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## License

This project is licensed under the [MIT License](LICENSE).
