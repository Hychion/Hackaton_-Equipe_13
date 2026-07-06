# Hackathon OVHcloud × Lille Ynov Campus — Équipe 13
## Chaîne d'audit & de remédiation GitOps sécurisée sur Kubernetes

> **La boucle cible :** détection d'une faille → analyse & correctif proposé par l'**IA** → **Pull Request automatique** sur Git → revue humaine → merge → **resynchronisation Argo CD** → cluster corrigé.

L'IA (OVH AI Endpoints) n'est pas un simple assistant : elle devient un **composant actif** de la chaîne de sécurité — le moteur qui transforme un rapport de vulnérabilité en correctif prêt à relire.

---

## 🧠 Idée directrice (à retenir)

**L'IA patche l'état désiré dans Git, jamais le cluster en direct.**
C'est tout l'intérêt du GitOps : Git est la source de vérité, Argo CD réconcilie le cluster vers Git. La revue humaine avant merge est le **garde-fou** qui empêche un correctif cassé (ou empoisonné) d'atteindre la production.

```
┌──────────────────────── Cluster Managed Kubernetes OVHcloud (3 nœuds) ────────────────────────┐
│                                                                                                │
│   workload vulnérable ──► Trivy-operator ──► (CRD VulnerabilityReport / ConfigAuditReport)     │
│          │                     │                                                               │
│          │  (admission)        └──► Prometheus ──► Grafana (courbe de CVE)                      │
│          ├──► Kyverno (policy-as-code, Audit)                                                   │
│          └──► Falco (runtime, eBPF)                                                             │
│                                    │                                                            │
│                          Remediator (CronJob, NOTRE code)                                       │
│                                    │  1. lit les rapports Trivy                                 │
│                                    │  2. lit le manifeste source dans Git                       │
│                                    ▼                                                            │
└────────────────────────────────── │ ────────────────────────────────────────────────────────┘
                                     │  3. prompt (rapport + manifeste)
                                     ▼
                          OVH AI Endpoints (Qwen3-Coder)  ──►  correctif YAML + explication
                                     │
                                     ▼  4. ouvre une Pull Request
                          Dépôt GitHub (source de vérité)  ◄── 5. revue humaine + merge
                                     │
                                     ▼  6. Argo CD resync ──► cluster corrigé
```

---

## 🧱 Stack (100 % CNCF, sauf la couche IA)

| Composant | Rôle | Statut CNCF | Licence |
|---|---|---|---|
| **Argo CD** | GitOps — synchronise Git → cluster | Graduated | Apache-2.0 |
| **Trivy-operator** | Audit sécurité (CVE + config) → CRD | Aqua Security, validé CNCF | Apache-2.0 |
| **Kyverno** | Policy-as-code — prévention de récidive | Graduated | Apache-2.0 |
| **Falco** | Détection de menaces au runtime (eBPF) | Graduated | Apache-2.0 |
| **Prometheus** (+ Grafana) | Observabilité & métriques | Graduated | Apache-2.0 (Grafana : **AGPL-3.0**) |
| **OVH AI Endpoints** | Couche IA générative (correctifs) | — (OVHcloud) | service |
| *(option)* **External Secrets Operator** | Secrets (token GitHub, clé IA) hors Git | Incubating | Apache-2.0 |
| *(option)* **Istio** | Service mesh (mTLS) | Graduated | Apache-2.0 |

> 📄 Détail des choix, du flux d'information et de l'ancrage cybersécurité (défense en profondeur, PRA, NIST CSF, supply chain) : **[`docs/architecture.md`](docs/architecture.md)**.

---

## 🗂️ Structure du dépôt

```
.
├── root-app.yaml            # app-of-apps : LA seule Application appliquée à la main.
│                            # Elle déploie tout le reste depuis Git.
├── infra/argocd-apps/       # une Application Argo CD par brique de la plateforme
│   ├── trivy-operator.yaml
│   ├── kyverno.yaml
│   ├── kyverno-policies.yaml
│   ├── falco.yaml
│   ├── monitoring.yaml      # kube-prometheus-stack
│   ├── vulnerable-app.yaml
│   └── remediator.yaml
├── apps/
│   ├── vulnerable-app/      # le workload volontairement vulnérable (la CIBLE)
│   └── remediator/          # NOTRE couche IA : code + Dockerfile + manifestes k8s
├── policies/                # ClusterPolicies Kyverno (disallow-privileged, require-limits…)
├── docs/                    # rapport d'architecture + tableau CNCF
└── secrets/                 # kubeconfig + clé IA — JAMAIS commit (voir .gitignore)
```

---

## 🚀 Démarrage (ordre d'installation)

> **Règle d'or GitOps :** après l'installation d'Argo CD, **plus rien ne s'installe à la main**. Tout passe par un commit + Argo CD. C'est ce que le jury regarde.

```bash
# 0. Pré-requis : kubectl, argocd (CLI), un kubeconfig dans secrets/
export KUBECONFIG=$PWD/secrets/kubeconfig-equipe-13.yaml
kubectl get nodes                                   # 3 nœuds Ready attendus

# 1. Installer Argo CD (la SEULE étape manuelle — on amorce la pompe)
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# 2. Bootstrap : appliquer l'app racine → elle déploie toute la plateforme depuis Git
kubectl apply -f root-app.yaml

# 3. Suivre la convergence
kubectl get applications -n argocd
```

Accès UI Argo CD :
```bash
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d; echo
kubectl port-forward svc/argocd-server -n argocd 8080:443   # https://localhost:8080  (admin / <mdp>)
```

---

## 📦 Livrables

- [x] Dépôt Git géré par Argo CD (ce repo)
- [ ] Code de la couche d'enrichissement IA → [`apps/remediator/`](apps/remediator/)
- [ ] Démo live de la boucle sur workloads vulnérables
- [ ] Rapport d'architecture → [`docs/architecture.md`](docs/architecture.md)

---

*Équipe 13 — Hackathon Lille Ynov Campus × OVHcloud, 6–7 juillet 2026.*
