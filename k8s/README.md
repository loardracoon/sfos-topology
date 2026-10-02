# Deploying to K3s via ArgoCD

## How it stays in sync

1. Push to `master`.
2. `.github/workflows/deploy.yml` builds the image, pushes it to
   `ghcr.io/loardracoon/sfos-topology:<commit-sha>`, then commits that tag
   into `k8s/app/deployment.yaml` (as `github-actions[bot]`, `[skip ci]`).
3. ArgoCD, watching `k8s/app/` on this repo, sees the new commit and syncs
   -- which rolls the Deployment to the new image.

Nothing here polls or pushes to the cluster directly from CI; the only thing
CI does to the cluster's desired state is commit to git, which is the point
of GitOps: `git log` on `k8s/app/` is the deploy history.

## One-time setup on the K3s host

**1. Install ArgoCD** (skip if already installed):

```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

**2. Create the fleet secret.** This is the one thing that never goes in
git -- same reasoning as `lab.env`/`devices.secrets.json` in the bare-binary
deployment. Run on the cluster, with real values:

```bash
kubectl create namespace sfos-topology
kubectl create secret generic sfos-fleet-secrets -n sfos-topology \
  --from-literal=SFOS_TOKEN_FW101='<token>' \
  --from-literal=SFOS_TOKEN_FW102='<token>' \
  --from-literal=SFOS_TOKEN_FW103='<token>' \
  --from-literal=SFOS_ADMIN_TOKEN='<optional, enables Settings + the policy matrix write endpoints>'
```

Add or remove `--from-literal` keys to match `k8s/app/configmap.yaml`'s
`tokenEnv` names if the fleet changes. Re-run `kubectl create secret ... -o
yaml --dry-run=client | kubectl apply -f -` instead of `create` if the
secret already exists and you're updating a value.

**3. Point ArgoCD at this repo:**

```bash
kubectl apply -f k8s/bootstrap/argocd-application.yaml
```

That's it -- ArgoCD creates the `sfos-topology` namespace, the ConfigMap,
the PVC, the Deployment and the Service from `k8s/app/`, and keeps them in
sync with git from then on.

## Checking it worked

```bash
kubectl -n sfos-topology get pods,svc,ingress
kubectl -n sfos-topology logs deploy/sfos-topology
kubectl -n sfos-topology port-forward svc/sfos-topology 8089:8089
# then open http://127.0.0.1:8089
```

Live at **http://topology.sophizo.com.br** (`k8s/app/ingress.yaml`, Traefik --
the same ingress class and pattern as the cluster's `wan-lab-manager` app).

## Exposure: open, by explicit choice

The viewer has no authentication of its own and renders internal network
addressing -- the same reasoning that keeps the Docker Compose deployment
bound to `127.0.0.1`. For this cluster the call was made to expose it
anyway, with no auth in front (no cert-manager is installed either, so it's
HTTP only, matching `wan-lab-manager`'s own ingress). If that changes,
either delete `k8s/app/ingress.yaml` to pull it back to ClusterIP-only, or
add a Traefik `BasicAuth` (or `IPAllowList`) middleware and reference it
from the Ingress's `traefik.ingress.kubernetes.io/router.middlewares`
annotation -- no code change needed either way.

## Why `devices.json` is a ConfigMap but secrets aren't

`devices.json` names *which* environment variable holds each appliance's API
key -- it never holds a key itself (see the README's "Credentials" section),
so it's exactly as safe to commit as the one in the repo root. The actual
key values live only in the `sfos-fleet-secrets` Secret, created by hand in
step 2 above, never written to this repo.
