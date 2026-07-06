# Rapport d'architecture — Chaîne d'audit & remédiation GitOps

**Hackathon OVHcloud × Lille Ynov Campus — Équipe 13 — juillet 2026**

---

## 1. Problème & objectif

Sur un cluster **Managed Kubernetes OVHcloud (3 nœuds)**, on veut auditer la sécurité en continu **et** corriger les vulnérabilités détectées, sans intervention manuelle risquée. La réponse : une **boucle GitOps** où l'**IA générative** produit les correctifs, sous contrôle humain.

> **Détection → analyse & correctif IA → Pull Request → revue humaine → merge → resync Argo CD → cluster corrigé.**

## 2. Principe directeur : patcher Git, pas le cluster

Le point d'architecture le plus important : **le correctif de l'IA modifie l'état désiré dans Git**, pas le cluster en direct.

- **Git est la source de vérité.** Argo CD réconcilie en permanence le cluster vers ce que décrit Git.
- L'IA ouvre une **Pull Request** → un humain relit et merge → Argo CD applique. Ce n'est pas un détail : c'est le **garde-fou** qui empêche une IA de pousser un correctif cassé en production (*never trust, always verify*).
- Corollaire résilience : le cluster est **reconstructible à l'identique** depuis Git (voir §6).

## 3. Flux d'information (qui parle à qui)

1. Un **workload volontairement vulnérable** est déployé par Argo CD (`apps/vulnerable-app`).
2. **Trivy-operator** le scanne et publie des CRD `VulnerabilityReport` (CVE d'image) et `ConfigAuditReport` (mauvaises configs). **C'est la matière première de l'IA.**
3. En parallèle : **Kyverno** évalue le Pod à l'admission (mode *Audit*), **Falco** surveille le runtime (eBPF), **Prometheus** collecte les métriques (dont le nombre de CVE).
4. Le **Remediator** (notre code, en **CronJob** dans le cluster) : lit les rapports Trivy → lit le manifeste source **dans Git** → envoie `{rapport + manifeste}` à **OVH AI Endpoints**.
5. L'IA renvoie un **manifeste corrigé + une explication** ; le Remediator ouvre une **Pull Request GitHub**.
6. **Revue humaine → merge → Argo CD resync** → le workload corrigé remplace l'ancien. Au scan suivant, le `VulnerabilityReport` fond ; la courbe Grafana chute.

## 4. Composants & justification des choix

| Composant | Pourquoi lui | Statut CNCF |
|---|---|---|
| **Argo CD** | Standard GitOps *Graduated* ; pattern **app-of-apps** (1 seule Application racine bootstrap tout le reste) → ajout d'une brique = 1 fichier + commit. | Graduated |
| **Trivy-operator** | Choisi plutôt que Kubescape : ses rapports en **CRD** sont directement lisibles par notre script (pas de parsing externe). Couvre **CVE + config** en un opérateur. | validé CNCF |
| **Kyverno** | Policy-as-code en YAML (pas de langage tiers). Mode **Audit** volontaire : en *Enforce* il bloquerait notre propre app vulnérable → plus rien à démontrer. Rôle = **empêcher la récidive** après correction. | Graduated |
| **Falco** | Seule brique **runtime** : détecte le comportement (shell ouvert, lecture `/etc/shadow`). Driver `modern_ebpf` → aucun module noyau à compiler (obligatoire sur cluster **managé**). | Graduated |
| **Prometheus + Grafana** | Observabilité ; surtout la **courbe de CVE qui chute** après merge = preuve visuelle de la boucle. | Graduated |
| **OVH AI Endpoints** | Couche IA imposée. Modèle **`Qwen3-Coder-30B`** (spécialisé code/YAML → manifestes plus fiables que les modèles généralistes). API **compatible OpenAI**. | — |
| **External Secrets Operator** | Secrets (token GitHub, clé IA) hors de Git. Brique **CNCF Incubating** → sécurise notre propre chaîne. | Incubating |

## 5. Décisions d'architecture (ADR condensés)

- **Remediator en CronJob in-cluster** (vs script lancé du poste) : 100 % GitOps, déployé par Argo CD, s'authentifie via un **ServiceAccount à RBAC lecture seule** sur les CRD Trivy (`load_incluster_config`). Pas de kubeconfig à transporter → moindre privilège.
- **Portée du correctif = config + image** : l'IA corrige les 4 familles de failles du workload (bump image pour les CVE, retrait de `privileged`, exécution non-root, ajout de `limits` CPU/mémoire) → aligne Trivy **et** Kyverno.
- **Secrets via ESO** (vs Secret K8s en clair) : token GitHub et clé IA ne sont **jamais** dans Git ; le Secret K8s est projeté depuis un coffre externe.
- **Validation du correctif** : le YAML de l'IA est passé en `kubectl apply --dry-run=server` (et `yaml.safe_load`) **avant** d'ouvrir la PR ; s'il est invalide, on redemande à l'IA avec le message d'erreur (boucle de retry).
- **Anti-doublon** : le Remediator vérifie qu'une PR `fix/ai-remediation` n'est pas déjà ouverte avant d'en créer une.

## 6. Ancrage cybersécurité (pourquoi c'est une *bonne* architecture)

**Défense en profondeur** — 4 couches indépendantes, chacune détecte autant qu'elle bloque :
`Trivy` (config statique) → `Kyverno` (admission) → `Falco` (runtime) → `Prometheus` (observabilité).

**Mapping NIST CSF** — la chaîne couvre les 5 fonctions du cadre :

| Fonction | Brique |
|---|---|
| Identify | Trivy (inventaire CVE/config, base d'un SBOM) |
| Protect | Kyverno (prévention) |
| Detect | Falco + Prometheus |
| Respond | **Remediator IA → Pull Request** |
| Recover | Argo CD (resync depuis Git) |

**Résilience / PRA** — Git = source de vérité ⇒ **RTO** minimal, **RPO** = dernier commit ; `selfHeal` restaure le drift. Rejouer la boucle (`git revert` → resync) *est* le test de bascule.

**Supply chain & réversibilité** — 100 % CNCF + Kubernetes standard = anti **vendor lock-in** ; le seul point de dépendance (OVH AI Endpoints) est neutralisé par l'**API compatible OpenAI** (changer `base_url` suffit à basculer de fournisseur/LLM). Vigilance licence : Grafana est en **AGPL-3.0** (copyleft réseau) — conforme en usage interne non redistribué.

## 7. Limites & suites

- Réglage fin des **ressources** sur 3 nœuds (réplicas à 1, requests basses, `alertmanager` désactivé) pour éviter les pods `Pending`.
- Remediator : boucler sur **tous** les rapports (pas seulement le premier) et sur les `ConfigAuditReport` + `PolicyReports` Kyverno.
- Enrichissement **Falco** : sur alerte runtime critique, demander à l'IA une analyse d'incident postée en issue GitHub.
- Durcissement : passer certaines policies Kyverno en *Enforce* une fois la démo faite ; option **Istio** pour le mTLS (Zero Trust réseau).

---

*Voir aussi le `README.md` (démarrage) et `apps/remediator/` (code de la couche IA).*
