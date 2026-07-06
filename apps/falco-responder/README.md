# Falco AI Responder (chantier B)

Étend l'IA à la **couche runtime**. Falco détecte un comportement suspect →
falcosidekick POST l'événement ici → l'IA (OVH AI Endpoints) l'analyse → une
**issue GitHub** est ouverte avec l'analyse et les recommandations.

```
Falco (eBPF) → falcosidekick → [webhook] → falco-ai-responder → OVH AI (gpt-oss-120b)
                                                    │
                                                    ▼
                                        issue GitHub (analyse d'incident)
```

## Fichiers
| Fichier | Rôle |
|---|---|
| `responder.py` | serveur Flask : reçoit l'alerte, appelle l'IA, ouvre l'issue |
| `k8s/deployment.yaml` | Deployment (non-root) + Service `falco-ai-responder:8080` |
| `k8s/namespace-secret.yaml` | namespace + ExternalSecret (token GitHub + clé IA via ESO) |
| `k8s/networkpolicy.yaml` | ingress depuis `falco` uniquement, egress DNS+443 |
| `kustomization.yaml` | injecte le code en ConfigMap |

## Sécurité
- Secrets via **ESO** (jamais en Git), conteneur **non-root** + `drop ALL`,
  **NetworkPolicy** stricte.
- Anti-spam : une issue par règle Falco.

## Tester (déclencher une alerte)
```bash
# Ouvre un shell dans un conteneur = comportement suspect détecté par Falco
kubectl -n demo exec -it deploy/vulnerable-web -- sh -c "cat /etc/shadow"
# → une issue "[Falco] ..." apparaît sur le dépôt GitHub
kubectl -n falco-responder logs -l app=falco-ai-responder
```
