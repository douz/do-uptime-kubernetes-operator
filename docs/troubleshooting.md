# Troubleshooting

## Operator is not reconciling

- Confirm deployment is running:

```bash
kubectl -n kube-system get deployment do-monitor-operator
```

- Check logs:

```bash
kubectl -n kube-system logs deployment/do-monitor-operator --tail=300
```

## Authentication errors with DigitalOcean

- Verify token secret exists and key name is correct.
- If using Helm-managed secret, check configured token value.
- If using existing secret, confirm `digitalocean.existingSecret` matches the secret name.

## Monitor not created from Ingress

- Confirm annotation `douz.io/do-monitor: "true"` is present.
- Verify Ingress has a valid host.
- Validate at least one notification channel is configured.
