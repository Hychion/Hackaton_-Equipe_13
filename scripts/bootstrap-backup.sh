#!/usr/bin/env bash
# Crée (hors Git) les credentials Garage + Velero. Idempotent : réutilise les
# secrets existants s'il y en a déjà (mêmes clés S3 côté Garage et Velero).
#   - garage-creds (backup-store) : rpc_secret, admin_token, clé S3 velero
#   - cloud-credentials (velero)  : mêmes clés S3, au format AWS attendu par Velero
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
export KUBECONFIG="${KUBECONFIG:-$DIR/secrets/kubeconfig-equipe-13.yaml}"

for ns in backup-store velero; do
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
done

# Réutilise les valeurs existantes si le secret garage-creds est déjà là.
get() { kubectl -n backup-store get secret garage-creds -o jsonpath="{.data.$1}" 2>/dev/null | base64 -d || true; }
RPC_SECRET="$(get rpc_secret)";    [ -z "$RPC_SECRET" ]  && RPC_SECRET="$(openssl rand -hex 32)"
ADMIN_TOKEN="$(get admin_token)";  [ -z "$ADMIN_TOKEN" ] && ADMIN_TOKEN="$(openssl rand -hex 32)"
S3_ACCESS="$(get s3_access_key)";  [ -z "$S3_ACCESS" ]   && S3_ACCESS="GK$(openssl rand -hex 12)"   # format Garage
S3_SECRET="$(get s3_secret_key)";  [ -z "$S3_SECRET" ]   && S3_SECRET="$(openssl rand -hex 32)"

# Secret Garage — lu par le serveur (rpc/admin) et par le job d'init (clé S3).
kubectl -n backup-store create secret generic garage-creds \
  --from-literal=rpc_secret="$RPC_SECRET" \
  --from-literal=admin_token="$ADMIN_TOKEN" \
  --from-literal=s3_access_key="$S3_ACCESS" \
  --from-literal=s3_secret_key="$S3_SECRET" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# Credentials Velero (format AWS S3) — mêmes clés que celles importées dans Garage.
kubectl -n velero create secret generic cloud-credentials \
  --from-literal=cloud="[default]
aws_access_key_id=$S3_ACCESS
aws_secret_access_key=$S3_SECRET" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

echo "OK — secrets garage-creds (backup-store) et cloud-credentials (velero) en place."
echo "   clé S3 velero (Garage) : $S3_ACCESS"

# --- Cible OFF-SITE : OVH Object Storage (S3) ---------------------------------
# Clés fournies via env (JAMAIS commitées). Avant de lancer :
#   export OVH_S3_ACCESS_KEY=... OVH_S3_SECRET_KEY=...
if [ -n "${OVH_S3_ACCESS_KEY:-}" ] && [ -n "${OVH_S3_SECRET_KEY:-}" ]; then
  kubectl -n velero create secret generic ovh-credentials \
    --from-literal=cloud="[default]
aws_access_key_id=$OVH_S3_ACCESS_KEY
aws_secret_access_key=$OVH_S3_SECRET_KEY" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  echo "OK — secret ovh-credentials (velero) en place (cible off-site OVH)."
else
  echo "ℹ️  ovh-credentials non créé : exporte OVH_S3_ACCESS_KEY / OVH_S3_SECRET_KEY pour la cible off-site OVH."
fi
