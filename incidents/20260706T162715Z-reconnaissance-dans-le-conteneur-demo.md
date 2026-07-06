# [Falco] Reconnaissance dans le conteneur demo

## Incident runtime détecté par Falco

**Règle :** Reconnaissance dans le conteneur demo
**Priorité :** Warning

```
16:26:52.923484062: Warning Commande de reconnaissance dans un conteneur (command=id user=<NA> container=web image=docker.io/nginxinc/nginx-unprivileged pod=vulnerable-web-8fd95dd69-qlkx9 ns=demo) container_id=8bda8b8e3476 container_name=web container_image_repository=docker.io/nginxinc/nginx-unprivileged container_image_tag=1.25.4 k8s_pod_name=vulnerable-web-8fd95dd69-qlkx9 k8s_ns_name=demo
```

## Analyse IA (OVH AI Endpoints — gpt-oss-120b)

**Ce qui s’est passé**  
- Un processus à l’intérieur du pod `vulnerable‑web-8fd95dd69-qlkx9` (namespace `demo`) a exécuté la commande `id`.  
- Le conteneur concerné utilise l’image `docker.io/nginxinc/nginx‑unprivileged:1.25.4` et porte le nom `web`.  
- Falco a déclenché la règle *“Commande de reconnaissance dans un conteneur”* (niveau Warning).

**Risque / Gravité**  
- **Vecteur d’attaque probable** : compromission du conteneur (ex. exploitation d’une vulnérabilité de l’image Nginx, fuite de secrets, ou accès via `kubectl exec`).  
- **Impact** : l’attaquant a déjà un accès à l’intérieur du conteneur et peut l’utiliser pour :  
  - Lister les UID/GID (`id`) → collecte d’informations d’identification.  
  - Explorer le système de fichiers, rechercher des secrets ou des tokens de service.  
  - Tenter une élévation de privilèges vers le nœud ou d’autres pods (pivot).  
- **Gravité** : **Moyenne à élevée** – la présence d’une activité de reconnaissance indique que la chaîne d’attaque a déjà franchi la première barrière (accès au conteneur). Si l’image n’est pas correctement sandboxée, le risque d’escalade ou de mouvement latéral augmente.

**Recommandations de remédiation (concrètes et actionnables)**  

1. **Renforcer la politique d’exécution des pods**  
   - Créez une règle Kyverno (ou OPA Gatekeeper) qui interdit l’usage de `kubectl exec` / `docker exec` sur les pods en production :  
     ```yaml
     apiVersion: kyverno.io/v1
     kind: ClusterPolicy
     metadata:
       name: deny-pod-exec
     spec:
       validationFailureAction: enforce
       rules:
       - name: block-exec
         match:
           resources:
             kinds: ["Pod"]
         validate:
           message: "L'exécution de commandes interactives dans les pods est interdite."
           pattern:
             spec:
               containers:
               - securityContext:
                   capabilities:
                     drop: ["ALL"]
     ```
   - Limitez les RBAC `exec` (`pods/exec`) aux comptes de service strictement nécessaires.

2. **Appliquer le principe du moindre privilège sur le conteneur**  
   - Ajoutez à la spécification du pod :  
     ```yaml
     securityContext:
       runAsNonRoot: true
       readOnlyRootFilesystem: true
       capabilities:
         drop: ["ALL"]
       seccompProfile:
         type: RuntimeDefault
     ```  
   - Utilisez une image **non‑privileged** signée et scannée (ex. `nginxinc/nginx-unprivileged` v1.25.4‑hardening) ou construisez votre propre image avec les binaires inutiles retirés.

3. **Activer la journalisation et la détection d’exec**  
   - Activez l’audit Kubernetes (`auditPolicy`) pour consigner tous les appels `pods/exec`.  
   - Configurez Falco (ou un autre runtime security) pour générer une alerte **Critical** lorsqu’une commande `exec` est détectée dans un pod non‑débogage.

4. **Remplacer l’image vulnérable et mettre en place une politique de mise à jour**  
   - Analysez l’image `nginxinc/nginx-unprivileged:1.25.4` avec un scanner (Trivy, Clair) ; si des CVE sont présents, migrez vers une version corrigée ou une image customisée.  
   - Déployez une policy Kyverno qui bloque le déploiement d’images non‑signées ou non‑scannées :  
     ```yaml
     apiVersion: kyverno.io/v1
     kind: ClusterPolicy
     metadata:
       name: require-image-scan
     spec:
       validationFailureAction: enforce
       rules:
       - name: check-image-scan
         match:
           resources:
             kinds: ["Pod"]
         validate:
           message: "L’image doit être scannée et approuvée avant le déploiement."
           pattern:
             spec:
               containers:
               - image: "?*"
                 # condition sur annotation ou label indiquant le résultat du scan
                 # (ex. `scan-status: passed`)
     ```

**Synthèse**  
L’exécution de `id` montre qu’un acteur a déjà un accès shell dans le conteneur. En appliquant les contrôles ci‑dessus (interdiction d’exec, renforcement du contexte de sécurité, audit des appels `exec`, et mise à jour de l’image), vous réduisez drastiquement le risque d’escalade et de mouvement latéral dans le cluster.

---
*Issue générée automatiquement par le falco-responder.*