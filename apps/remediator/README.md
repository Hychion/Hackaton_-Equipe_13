# Remediator IA — la couche d'enrichissement

La brique centrale du hackathon : elle transforme les rapports de sécurité du
cluster en une **Pull Request de correctif générée par l'IA**.

## La boucle

```
VulnerabilityReport + ConfigAuditReport (Trivy, dans le cluster)
        │  1. lecture (RBAC lecture seule)
        ▼
   résumé priorisé des failles
        │  2. + manifeste actuel lu dans Git (source de vérité)
        ▼
   OVH AI Endpoints — Qwen3.6-27B          3. prompt
        │  4. manifeste corrigé + explication (YAML validé)
        ▼
   Pull Request GitHub  ──►  revue humaine  ──►  merge  ──►  Argo CD resync
```

**On patche Git, jamais le cluster.** La revue humaine avant merge est le
garde-fou (*never trust, always verify* appliqué à l'IA).

## Fichiers

| Fichier | Rôle |
|---|---|
| `remediator.py` | le code (lecture rapports → IA → PR), source de vérité |
| `requirements.txt` | dépendances (openai, PyGithub, kubernetes, pyyaml) |
| `kustomization.yaml` | injecte le code dans une ConfigMap (pas de registry d'image) |
| `k8s/rbac.yaml` | ServiceAccount + ClusterRole **lecture seule** sur les CRD Trivy |
| `k8s/cronjob.yaml` | CronJob (python:3.12-slim, non-root), secrets via ESO |

## Sécurité de la brique

- **RBAC minimal** : lecture seule des rapports Trivy, aucun droit d'écriture cluster.
- **Secrets via ESO** : `OVH_AI_TOKEN` + `GITHUB_TOKEN` projetés depuis le store,
  jamais dans Git ni dans l'image.
- **Conteneur non-root**, `capabilities: drop ALL`, `allowPrivilegeEscalation: false`.
- **NetworkPolicy** : pas d'ingress, egress limité à DNS + 443.
- **Garde-fous IA** : YAML parsé + vérifié (doit rester un Deployment) avant PR ;
  anti-doublon (ne rouvre pas une PR déjà ouverte).

## Config (variables d'environnement)

| Variable | Exemple | Source |
|---|---|---|
| `OVH_AI_BASE_URL` | `https://oai.endpoints.kepler.ai.cloud.ovh.net/v1` | manifeste |
| `OVH_AI_MODEL` | `Qwen3.6-27B` | manifeste |
| `OVH_AI_TOKEN` | *(clé AI Endpoints)* | **ESO** |
| `GITHUB_TOKEN` | *(PAT fine-grained)* | **ESO** |
| `GITHUB_REPO` | `Hychion/Hackaton_-Equipe_13` | manifeste |
| `MANIFEST_PATH` | `apps/vulnerable-app/deployment.yaml` | manifeste |
| `TARGET_NAMESPACE` | `demo` | manifeste |

## Lancer

Déployé en GitOps (Application `remediator`). Déclencher un run à la demande :

```bash
kubectl -n remediator create job --from=cronjob/remediator run-demo
kubectl -n remediator logs -f job/run-demo
```

Test local (hors cluster) : `pip install -r requirements.txt`, exporter les
variables ci-dessus, `python remediator.py` (utilise `~/.kube/config`).
