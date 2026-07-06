# ClusterPolicies Kyverno — prévention de la récidive

Ces policies **ferment la boucle** : une fois qu'un correctif de l'IA est mergé,
Kyverno empêche la même classe de faille de réapparaître.

## Choix de conception

- **Mode `Audit`** (et non `Enforce`) : les policies **signalent** les violations
  (via des `PolicyReports`) sans **bloquer**. En `Enforce`, Kyverno refuserait à
  l'admission notre propre workload vulnérable — et on n'aurait plus rien à
  démontrer. Après la démo, on peut basculer les policies en `Enforce`.
- **Scope `namespace: demo`** : les règles ne s'appliquent qu'au namespace de démo,
  pour ne pas flaguer nos propres briques de sécurité (Falco tourne légitimement
  en privilégié, par exemple).
- **Syntaxe Kyverno v1.18** : `failureAction` au niveau de la **règle** (le champ
  `spec.validationFailureAction` a été retiré des versions récentes).

## Les 3 policies

| Fichier | Règle | Faille couverte (dans le workload de démo) |
|---|---|---|
| `disallow-privileged.yaml` | Pas de conteneur `privileged` | FAILLE 2 |
| `require-limits.yaml` | `limits` CPU + mémoire obligatoires | FAILLE 4 |
| `disallow-latest-tag.yaml` | Interdit le tag `:latest` | bonne pratique image |

## Voir les violations

```bash
kubectl get policyreports -n demo
kubectl get policyreports -n demo -o yaml   # détail : quelle policy, quel pod, quel message
```

Déployées en GitOps via l'Application `kyverno-policies` (`infra/argocd-apps/kyverno-policies.yaml`).
