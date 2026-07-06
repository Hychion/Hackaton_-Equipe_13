#!/usr/bin/env bash
# Crée le secret SOURCE `chain-secrets` dans le namespace secret-store, à partir
# des fichiers locaux (gitignore). C'est la SEULE étape secrète manuelle, comme
# l'install d'Argo CD : le matériel sensible n'entre jamais dans Git.
# ESO lit ensuite ce secret et le projette (voir infra/security/).
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
export KUBECONFIG="${KUBECONFIG:-$DIR/secrets/kubeconfig-equipe-13.yaml}"

GH_TOKEN=$(tr -d ' \t\n\r' < "$DIR/secrets/github-token.txt")
AI_TOKEN=$(tr -d ' \t\n\r' < "$DIR/secrets/ai-endpoints-key.txt")

kubectl create namespace secret-store --dry-run=client -o yaml | kubectl apply -f -
kubectl -n secret-store create secret generic chain-secrets \
  --from-literal=github-token="$GH_TOKEN" \
  --from-literal=ovh-ai-token="$AI_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "OK — secret 'chain-secrets' présent dans le namespace secret-store."
echo "ESO va le projeter en 'chain-credentials' (namespace remediator)."
