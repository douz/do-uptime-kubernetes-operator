# DigitalOcean Uptime Monitor Operator

This Kubernetes operator automates the creation, update, and deletion of [DigitalOcean Uptime Monitors](https://docs.digitalocean.com/products/monitoring/) and related alerts based on Ingress annotations.

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/douz/do-uptime-kubernetes-operator
   cd do-uptime-kubernetes-operator
   ```

2. **Create Kubernetes Secret**  
   Update the `token` value in `03-do-token-secret.yaml` with your DigitalOcean API key (base64-encoded).

3. **Apply the CRD, RBAC, Secret and Operator Manifests** 
   ```bash
   kubectl apply -f manifests/01-do-monitor-crd.yaml
   kubectl apply -f manifests/02-rbac.yaml
   kubectl apply -f manifests/03-do-token-secret.yaml
   kubectl apply -f manifests/04-operator-deployment.yaml
   ```

## Usage

The `do-monitor-operator` will watch for Ingress resources with the `douz.com/do-monitor: "true"` annotation and create the Uptime Monitor and associated alerts accordingly. For example:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  namespace: default
  annotations:
    douz.com/do-monitor: "true"
    douz.com/do-monitor-email: "your-email@example.com"
    douz.com/do-monitor-slack-webhook: "https://hooks.slack.com/services/your/slack/webhook"
    douz.com/do-monitor-slack-channel: "#your-slack-channel"
    douz.com/do-monitor-latency-threshold: "200"
    douz.com/do-monitor-latency-period: "2m"
    douz.com/do-monitor-ssl-expiry: "30"
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

In this example, an Uptime Monitor (check) named `example-ingress-default-domonitor` (`<ingressName>-<namespace>-domonitor`) will be created, along with `down`, `latency`, and `sslExpiry` alerts, sending notifications to the specified email address and Slack channel.

### Monitoring Annotations

- **`douz.com/do-monitor`:** Set to `"true"` to enable the operator for an Ingress resource.
- **`douz.com/do-monitor-email`:** Email address to send alerts to (only verified emails in the DigitalOcean dashboard will work).
- **`douz.com/do-monitor-slack-webhook`:** Slack webhook URL for sending alerts to a channel.
- **`douz.com/do-monitor-slack-channel`:** Slack channel name (e.g., `#your-slack-channel`).
- **`douz.com/do-monitor-latency-threshold`:** Latency threshold in milliseconds.
- **`douz.com/do-monitor-latency-period`:** Period over which to measure latency (e.g., `"2m"`).
- **`douz.com/do-monitor-ssl-expiry`:** Number of days before SSL certificate expiry to trigger an alert.

At least one notification channel(email or Slack) must be provided.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests. Please follow the [DigitalOcean Uptime Monitor docs](https://docs.digitalocean.com/products/monitoring/) and [Kubernetes Operator patterns](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) when making changes.

## License

This project is licensed under the [MIT License](LICENSE).