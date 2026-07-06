#!/usr/bin/env python3
"""
Remediator IA — Hackathon OVHcloud × Ynov (équipe 13)
=====================================================
La brique centrale : transforme les rapports de sécurité du cluster en Pull
Requests de correctif, générées par l'IA — pour PLUSIEURS applications.

Boucle (pour chaque cible) :
  rapports Trivy du workload → résumé → OVH AI Endpoints → manifeste corrigé
  → Pull Request GitHub (branche par workload) → revue humaine → merge → Argo CD.

Principe : on patche l'ÉTAT DÉSIRÉ dans Git, jamais le cluster en direct.

Config (env) :
  OVH_AI_BASE_URL / OVH_AI_MODEL / OVH_AI_TOKEN   (IA, token via ESO)
  GITHUB_TOKEN (ESO) / GITHUB_REPO / GIT_BRANCH (def: main)
  TARGETS : JSON [{"namespace","workload","manifest_path"}, ...]
            (à défaut : cible unique TARGET_NAMESPACE/WORKLOAD/MANIFEST_PATH)
"""
import json
import os
import re
import sys

import yaml
from openai import OpenAI
from github import Github, GithubException, Auth
from kubernetes import client, config

OVH_AI_BASE_URL = os.environ["OVH_AI_BASE_URL"]
OVH_AI_MODEL = os.environ["OVH_AI_MODEL"]
OVH_AI_TOKEN = os.environ["OVH_AI_TOKEN"]
GITHUB_REPO = os.environ["GITHUB_REPO"]
GIT_BRANCH = os.environ.get("GIT_BRANCH", "main")


def load_targets():
    raw = os.environ.get("TARGETS", "").strip()
    if raw:
        return json.loads(raw)
    return [{
        "namespace": os.environ.get("TARGET_NAMESPACE", "demo"),
        "workload": os.environ.get("WORKLOAD", "vulnerable-web"),
        "manifest_path": os.environ.get("MANIFEST_PATH", "apps/vulnerable-app/deployment.yaml"),
    }]


# --------------------------------------------------------------------------- #
# 1. Lire les rapports Trivy du workload ciblé
# --------------------------------------------------------------------------- #
def load_k8s():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CustomObjectsApi()


def _matches(report, workload):
    name = report.get("metadata", {}).get("labels", {}).get("trivy-operator.resource.name", "")
    return name == workload or name.startswith(workload + "-")


def get_reports(api, plural, namespace, workload):
    try:
        items = api.list_namespaced_custom_object(
            "aquasecurity.github.io", "v1alpha1", namespace, plural)["items"]
    except client.ApiException as exc:
        print(f"  ! lecture {plural} impossible: {exc.reason}")
        return []
    return [r for r in items if _matches(r, workload)]


def summarize(vuln_reports, config_reports, max_cves=15):
    lines, order = [], {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    for rep in vuln_reports:
        art = rep.get("report", {}).get("artifact", {})
        summary = rep.get("report", {}).get("summary", {})
        vulns = rep.get("report", {}).get("vulnerabilities", [])
        lines.append(f"\nImage {art.get('repository','?')}:{art.get('tag','?')} — "
                     f"CRITICAL={summary.get('criticalCount',0)} HIGH={summary.get('highCount',0)}")
        vulns.sort(key=lambda v: order.get(str(v.get("severity", "")).upper(), 9))
        for v in vulns[:max_cves]:
            lines.append(f"  - {v.get('vulnerabilityID')} [{v.get('severity')}] {v.get('resource')} "
                         f"{v.get('installedVersion','?')} -> fix: {v.get('fixedVersion','n/a')}")
    for rep in config_reports:
        failed = [c for c in rep.get("report", {}).get("checks", []) if not c.get("success", True)]
        if failed:
            lines.append("\nMauvaises configurations (Trivy config audit) :")
            for c in failed[:max_cves]:
                lines.append(f"  - [{c.get('severity')}] {c.get('checkID')}: {c.get('title')}")
    return "\n".join(lines) if lines else ""


# --------------------------------------------------------------------------- #
# 2. Lire le manifeste dans Git  /  3. Demander le correctif à l'IA
# --------------------------------------------------------------------------- #
def get_manifest(repo, path):
    f = repo.get_contents(path, ref=GIT_BRANCH)
    return f.decoded_content.decode(), f.sha


SYSTEM_PROMPT = """Tu es un expert en sécurité Kubernetes.
On te donne (1) un résumé de vulnérabilités et mauvaises configurations détectées
par Trivy, et (2) le manifeste YAML actuel du workload concerné.

Ta mission : produire le manifeste YAML CORRIGÉ qui :
- met à jour l'image vers une version récente et maintenue corrigeant les CVE.
  IMPORTANT : conserve le MÊME dépôt d'image (ne change QUE le tag) ;
- supprime privileged (le retire ou le met à false) ;
- fait tourner le conteneur en utilisateur NON-root (runAsNonRoot: true,
  runAsUser >= 1000, allowPrivilegeEscalation: false). Ne change PAS le
  containerPort existant ;
- ajoute des requests ET limits CPU/mémoire raisonnables ;
- garde un Deployment VALIDE et minimal : mêmes name, namespace, labels, selector.

Corrige UNIQUEMENT ces points. N'ajoute PAS readOnlyRootFilesystem ni d'autres
contraintes de durcissement qui pourraient empêcher le conteneur de démarrer.

Réponds STRICTEMENT dans ce format, sans texte autour :
EXPLICATION:
<3 à 6 lignes en français expliquant chaque correction>
YAML:
```yaml
<le manifeste complet corrigé>
```"""


def ask_ai(ai, report_summary, current_manifest):
    resp = ai.chat.completions.create(
        model=OVH_AI_MODEL, temperature=0.1, max_tokens=4000,
        messages=[{"role": "system", "content": SYSTEM_PROMPT},
                  {"role": "user", "content":
                   f"RAPPORT TRIVY :\n{report_summary}\n\nMANIFESTE ACTUEL :\n{current_manifest}"}],
    )
    text = resp.choices[0].message.content
    match = re.search(r"```(?:yaml)?\s*\n(.*?)```", text, re.DOTALL)
    if not match:
        raise ValueError(f"L'IA n'a pas renvoyé de bloc YAML :\n{text}")
    fixed_yaml = match.group(1).strip() + "\n"
    explanation = text.split("YAML:")[0].replace("EXPLICATION:", "").strip()
    doc = yaml.safe_load(fixed_yaml)
    if not isinstance(doc, dict) or doc.get("kind") != "Deployment":
        raise ValueError("Le YAML corrigé n'est pas un Deployment valide.")
    return explanation, fixed_yaml


# --------------------------------------------------------------------------- #
# 4 & 5. Ouvrir la Pull Request (une branche par workload, sans doublon)
# --------------------------------------------------------------------------- #
def open_pull_request(repo, target, file_sha, fixed_yaml, explanation, report_summary):
    branch = f"fix/ai-remediation-{target['workload']}"
    for pr in repo.get_pulls(state="open"):
        if pr.head.ref == branch:
            print(f"  = PR déjà ouverte pour {target['workload']} : {pr.html_url}")
            return pr.html_url
    main_ref = repo.get_branch(GIT_BRANCH)
    try:
        repo.get_git_ref(f"heads/{branch}").delete()
    except GithubException:
        pass
    repo.create_git_ref(ref=f"refs/heads/{branch}", sha=main_ref.commit.sha)
    repo.update_file(
        path=target["manifest_path"],
        message=f"fix(security): remédiation IA — {target['workload']}",
        content=fixed_yaml, sha=file_sha, branch=branch)
    pr = repo.create_pull(
        title=f"[IA] Remédiation — {target['workload']}",
        body=(f"## Correctif proposé par l'IA (OVH AI Endpoints — {OVH_AI_MODEL})\n\n"
              f"**Workload :** `{target['workload']}` (namespace `{target['namespace']}`)\n\n"
              f"{explanation}\n\n"
              f"## Rapport de sécurité\n```\n{report_summary}\n```\n\n"
              f"---\n*PR générée automatiquement — **relecture humaine requise avant merge.***"),
        head=branch, base=GIT_BRANCH)
    return pr.html_url


# --------------------------------------------------------------------------- #
# Orchestration multi-cibles
# --------------------------------------------------------------------------- #
def remediate(api, ai, repo, target):
    ns, wl = target["namespace"], target["workload"]
    print(f"\n== Cible {ns}/{wl} ({target['manifest_path']}) ==")
    vuln = get_reports(api, "vulnerabilityreports", ns, wl)
    conf = get_reports(api, "configauditreports", ns, wl)
    print(f"  rapports : {len(vuln)} vulnerability, {len(conf)} configaudit")
    summary = summarize(vuln, conf)
    if not summary:
        print("  aucune faille exploitable — rien à faire.")
        return
    manifest, sha = get_manifest(repo, target["manifest_path"])
    print("  == appel à l'IA ==")
    explanation, fixed_yaml = ask_ai(ai, summary, manifest)
    url = open_pull_request(repo, target, sha, fixed_yaml, explanation, summary)
    print(f"  ✅ Pull Request : {url}")


def main():
    api = load_k8s()
    ai = OpenAI(base_url=OVH_AI_BASE_URL, api_key=OVH_AI_TOKEN, timeout=180.0, max_retries=2)
    repo = Github(auth=Auth.Token(os.environ["GITHUB_TOKEN"])).get_repo(GITHUB_REPO)
    targets = load_targets()
    print(f"== Remediator — {len(targets)} cible(s) — repo {GITHUB_REPO} ==")
    failures = 0
    for t in targets:
        try:
            remediate(api, ai, repo, t)
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"  ERREUR sur {t.get('workload')}: {exc}", file=sys.stderr)
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
