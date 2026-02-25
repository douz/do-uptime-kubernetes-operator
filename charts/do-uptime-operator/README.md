# do-uptime-operator Helm Chart

## Install

```bash
helm upgrade --install do-uptime-operator charts/do-uptime-operator \
  --namespace kube-system \
  --create-namespace \
  --set digitalocean.createSecret=true \
  --set digitalocean.token='<DIGITALOCEAN_TOKEN>'
```

## Use Existing Secret

```bash
helm upgrade --install do-uptime-operator charts/do-uptime-operator \
  --namespace kube-system \
  --create-namespace \
  --set digitalocean.createSecret=false \
  --set digitalocean.existingSecret=do-token-secret
```

The secret must contain a `token` key.

## Values

- `image.repository`: Operator image repository.
- `image.tag`: Operator image tag.
- `serviceAccount.create`: Create a ServiceAccount.
- `rbac.create`: Create ClusterRole/ClusterRoleBinding.
- `digitalocean.createSecret`: Create secret with token.
- `digitalocean.existingSecret`: Existing secret name used when `createSecret=false`.
- `resources`: Container resources.
 
