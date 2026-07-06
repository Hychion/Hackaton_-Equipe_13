# Multi-cluster — promotion pré-prod → prod + miroir prod

Extension résilience de la chaîne (branche `feat/multi-cluster`). **Prête, non
activée** : aucun cluster supplémentaire requis pour la préparer ; on branche
dès qu'un kubeconfig arrive.

## Les environnements

```
envs/
├── preprod/vulnerable-app/   ← le SAS : le remediator patche ICI d'abord
└── prod/vulnerable-app/      ← promu après validation en pré-prod
```

- **Pré-prod** = 1 cluster séparé (petit / flavor réduit). Reçoit les correctifs
  de l'IA en premier, pour les **tester avant la prod**.
- **Prod** = 1 cluster (l'actuel équipe-13) + éventuellement 1 **miroir**.

## Le flux de promotion (enrichit la boucle IA)

```
Trivy détecte (pré-prod)
   → IA patche envs/preprod/…  (1ʳᵉ PR)
   → Argo applique en PRÉ-PROD → tests OK
   → PR de promotion (envs/preprod → envs/prod)  (revue humaine)
   → Argo applique en PROD (et sur tous les miroirs)
```
> Rien n'atteint la prod sans passer le **sas pré-prod**. C'est le palier de
> validation qui protège la production.

## Le miroir prod (HA / DR)

`vulnerable-app-prod-mirror.yaml` = un **ApplicationSet** avec *cluster generator* :
il déploie `envs/prod/` sur **tous les clusters taggés `env=prod`**. Ajouter un
miroir = enregistrer un 2e cluster prod → il devient identique par construction
(pattern **actif/passif** recommandé). Voir la note vault
`Resilience-Redondance` pour les pièges (failover DNS, état/BDD, où vit Argo CD).

## 🔌 Activation (quand les clusters existent)

1. **Enregistrer les clusters dans Argo CD** (Argo tourne dans le cluster prod) :
   ```bash
   argocd cluster add <context-preprod> --name preprod --label env=preprod
   argocd cluster add <context-prod-1>  --name prod-1  --label env=prod
   # (plus tard, le miroir)
   argocd cluster add <context-prod-2>  --name prod-2  --label env=prod
   ```
2. **Déployer les Applications d'environnement** :
   ```bash
   kubectl apply -f envs/argocd-apps/
   ```
3. **Pointer le remediator sur la pré-prod** (variable d'env de la CronJob) :
   ```
   MANIFEST_PATH = envs/preprod/vulnerable-app/deployment.yaml
   ```
   → l'IA patchera pré-prod en premier ; la promotion vers `envs/prod` reste une
   PR humaine (le sas).

## Coût / pragmatisme

3 clusters (prod-1 + miroir + pré-prod) = 3× nœuds facturés. Option sobre :
**1 prod + 1 pré-prod** en continu, le **miroir** provisionné juste pour la
démo de soutenance (ApplicationSet déjà prêt) puis supprimé.
