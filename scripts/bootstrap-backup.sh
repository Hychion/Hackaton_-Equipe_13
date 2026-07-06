#!/usr/bin/env bash
# Crée (hors Git) les credentials MinIO + Velero. Idempotent : réutilise le mot
# de passe existant s'il y en a déjà un.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
export KUBECONFIG="${KUBECONFIG:-$DIR/secrets/kubeconfig-equipe-13.yaml}"

USER="velero"
PASS="$(kubectl -n backup-store get secret minio-creds -o jsonpath='{.data.MINIO_ROOT_PASSWORD}' 2>/dev/null | base64 -d || true)"
[ -z "$PASS" ] && PASS="$(openssl rand -hex 20)"

for ns in backup-store velero; do
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
done

# Credentials MinIO (root) — lus par MinIO et le job de création de bucket.
kubectl -n backup-store create secret generic minio-creds \
  --from-literal=MINIO_ROOT_USER="$USER" \
  --from-literal=MINIO_ROOT_PASSWORD="$PASS" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# Credentials Velero (format AWS S3) — mêmes clés que MinIO.
kubectl -n velero create secret generic cloud-credentials \
  --from-literal=cloud="[default]
aws_access_key_id=$USER
aws_secret_access_key=$PASS" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

echo "OK — secrets minio-creds (backup-store) et cloud-credentials (velero) en place."
