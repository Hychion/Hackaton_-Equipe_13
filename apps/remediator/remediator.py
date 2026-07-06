#!/usr/bin/env python3
"""
Remediator IA — Hackathon OVHcloud × Ynov (équipe 13)
=====================================================
La brique centrale : transforme les rapports de sécurité du cluster en une
Pull Request de correctif, générée par l'IA.

Boucle :  rapports Trivy (cluster)  ->  résumé  ->  OVH AI Endpoints (Qwen3-Coder)
          ->  manifeste corrigé  ->  Pull Request GitHub  ->  (revue humaine)

Principe : on patche l'ÉTAT DÉSIRÉ dans Git, jamais le cluster en direct.
La revue humaine avant merge est le garde-fou (never trust, always verify).

Config (variables d'environnement) :
  OVH_AI_BASE_URL   ex. https://oai.endpoints.kepler.ai.cloud.ovh.net/v1
  OVH_AI_MODEL      ex. Qwen3-Coder-30B-A3B-Instruct
  OVH_AI_TOKEN      clé AI Endpoints            (injectée par ESO)
  GITHUB_TOKEN      PAT fine-grained            (injecté par ESO)
  GITHUB_REPO       ex. Hychion/Hackaton_-Equipe_13
  MANIFEST_PATH     ex. apps/vulnerable-app/deployment.yaml
  TARGET_NAMESPACE  ex. demo
  GIT_BRANCH        ex. main
"""
import os
import re
import sys

import yaml
from openai import OpenAI
from github import Github, GithubException
from kubernetes import client, config

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
OVH_AI_BASE_URL = os.environ["OVH_AI_BASE_URL"]
OVH_AI_MODEL = os.environ["OVH_AI_MODEL"]
OVH_AI_TOKEN = os.environ["OVH_AI_TOKEN"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPO = os.environ["GITHUB_REPO"]
MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "apps/vulnerable-app/deployment.yaml")
TARGET_NAMESPACE = os.environ.get("TARGET_NAMESPACE", "demo")
GIT_BRANCH = os.environ.get("GIT_BRANCH", "main")
FIX_BRANCH = os.environ.get("FIX_BRANCH", "fix/ai-remediation")


# --------------------------------------------------------------------------- #
# 1. Lire les rapports de sécurité (Trivy) dans le cluster
# --------------------------------------------------------------------------- #
def load_k8s():
    """En cluster (ServiceAccount) ou en local (~/.kube/config) pour tester."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CustomObjectsApi()


def get_reports(api, plural):
    try:
        return api.list_namespaced_custom_object(
            group="aquasecurity.github.io",
            version="v1alpha1",
            namespace=TARGET_NAMESPACE,
            plural=plural,
        )["items"]
    except client.ApiException as exc:
        print(f"  ! lecture {plural} impossible: {exc.reason}")
        return []


def summarize(vuln_reports, config_reports, max_cves=15):
    """Résumé compact et priorisé pour le prompt (on garde l'essentiel)."""
    lines = []
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    for rep in vuln_reports:
        art = rep.get("report", {}).get("artifact", {})
        summary = rep.get("report", {}).get("summary", {})
        vulns = rep.get("report", {}).get("vulnerabilities", [])
        lines.append(
            f"\nImage {art.get('repository','?')}:{art.get('tag','?')} — "
            f"CRITICAL={summary.get('criticalCount',0)} HIGH={summary.get('highCount',0)}"
        )
        vulns.sort(key=lambda v: order.get(str(v.get("severity", "")).upper(), 9))
        for v in vulns[:max_cves]:
            lines.append(
                f"  - {v.get('vulnerabilityID')} [{v.get('severity')}] {v.get('resource')} "
                f"{v.get('installedVersion','?')} -> fix: {v.get('fixedVersion','n/a')}"
            )

    for rep in config_reports:
        checks = rep.get("report", {}).get("checks", [])
        failed = [c for c in checks if not c.get("success", True)]
        if failed:
            lines.append("\nMauvaises configurations (Trivy config audit) :")
            for c in failed[:max_cves]:
                lines.append(f"  - [{c.get('severity')}] {c.get('checkID')}: {c.get('title')}")

    return "\n".join(lines) if lines else ""


# --------------------------------------------------------------------------- #
# 2. Lire le manifeste source dans Git (source de vérité)
# --------------------------------------------------------------------------- #
def get_manifest(repo):
    f = repo.get_contents(MANIFEST_PATH, ref=GIT_BRANCH)
    return f.decoded_content.decode(), f.sha


# --------------------------------------------------------------------------- #
# 3. Demander le correctif à l'IA (OVH AI Endpoints, Qwen3-Coder)
# --------------------------------------------------------------------------- #
SYSTEM_PROMPT = """Tu es un expert en sécurité Kubernetes.
On te donne (1) un résumé de vulnérabilités et mauvaises configurations détectées
par Trivy, et (2) le manifeste YAML actuel du workload concerné.

Ta mission : produire le manifeste YAML CORRIGÉ qui :
- met à jour l'image vers une version récente et maintenue corrigeant les CVE.
  IMPORTANT : conserve le MÊME dépôt d'image (ne change QUE le tag) ;
- supprime privileged (le retire ou le met à false) ;
- fait tourner le conteneur en utilisateur NON-root (runAsNonRoot: true,
  runAsUser >= 1000, allowPrivilegeEscalation: false). Ne change PAS le
  containerPort existant (il est déjà > 1024, compatible non-root) ;
- ajoute des requests ET limits CPU/mémoire raisonnables ;
- garde un Deployment VALIDE et minimal : mêmes name, namespace, labels, selector.

Réponds STRICTEMENT dans ce format, sans texte autour :
EXPLICATION:
<3 à 6 lignes en français expliquant chaque correction>
YAML:
```yaml
<le manifeste complet corrigé>
```"""


def ask_ai(report_summary, current_manifest):
    ai = OpenAI(base_url=OVH_AI_BASE_URL, api_key=OVH_AI_TOKEN,
                timeout=180.0, max_retries=2)  # ne pas bloquer indéfiniment
    resp = ai.chat.completions.create(
        model=OVH_AI_MODEL,
        temperature=0.1,  # peu de créativité : on veut du YAML fiable
        # Qwen3.6-27B est un modèle "reasoning" : la réflexion consomme des tokens
        # avant la réponse → budget large pour laisser sortir le YAML complet.
        max_tokens=4000,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",
             "content": f"RAPPORT TRIVY :\n{report_summary}\n\nMANIFESTE ACTUEL :\n{current_manifest}"},
        ],
    )
    text = resp.choices[0].message.content

    # Extraction robuste des deux blocs
    match = re.search(r"```(?:yaml)?\s*\n(.*?)```", text, re.DOTALL)
    if not match:
        raise ValueError(f"L'IA n'a pas renvoyé de bloc YAML :\n{text}")
    fixed_yaml = match.group(1).strip() + "\n"

    explanation = text.split("YAML:")[0].replace("EXPLICATION:", "").strip()

    # Garde-fou : le YAML doit être parsable et rester un Deployment
    doc = yaml.safe_load(fixed_yaml)
    if not isinstance(doc, dict) or doc.get("kind") != "Deployment":
        raise ValueError("Le YAML corrigé n'est pas un Deployment valide.")
    return explanation, fixed_yaml


# --------------------------------------------------------------------------- #
# 4 & 5. Ouvrir la Pull Request (sans doublon)
# --------------------------------------------------------------------------- #
def open_pull_request(repo, file_sha, fixed_yaml, explanation, report_summary):
    # Anti-doublon : ne pas rouvrir une PR fix déjà ouverte
    for pr in repo.get_pulls(state="open"):
        if pr.head.ref == FIX_BRANCH:
            print(f"  = PR déjà ouverte : {pr.html_url} — on ne duplique pas.")
            return pr.html_url

    main_ref = repo.get_branch(GIT_BRANCH)
    try:
        repo.get_git_ref(f"heads/{FIX_BRANCH}").delete()
    except GithubException:
        pass
    repo.create_git_ref(ref=f"refs/heads/{FIX_BRANCH}", sha=main_ref.commit.sha)

    repo.update_file(
        path=MANIFEST_PATH,
        message="fix(security): remédiation automatique proposée par l'IA",
        content=fixed_yaml,
        sha=file_sha,
        branch=FIX_BRANCH,
    )
    pr = repo.create_pull(
        title="[IA] Remédiation automatique des vulnérabilités détectées",
        body=(f"## Correctif proposé par l'IA (OVH AI Endpoints — {OVH_AI_MODEL})\n\n"
              f"{explanation}\n\n"
              f"## Rapport de sécurité ayant déclenché l'analyse\n"
              f"```\n{report_summary}\n```\n\n"
              f"---\n*PR générée automatiquement par le remediator — "
              f"**relecture humaine requise avant merge.***"),
        head=FIX_BRANCH,
        base=GIT_BRANCH,
    )
    return pr.html_url


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def main():
    print(f"== Remediator — namespace={TARGET_NAMESPACE} repo={GITHUB_REPO} ==")
    api = load_k8s()
    vuln = get_reports(api, "vulnerabilityreports")
    conf = get_reports(api, "configauditreports")
    print(f"  rapports : {len(vuln)} vulnerability, {len(conf)} configaudit")

    summary = summarize(vuln, conf)
    if not summary:
        print("  aucune faille exploitable dans les rapports — rien à faire.")
        return

    repo = Github(GITHUB_TOKEN).get_repo(GITHUB_REPO)
    manifest, sha = get_manifest(repo)

    print("  == appel à l'IA (OVH AI Endpoints) ==")
    explanation, fixed_yaml = ask_ai(summary, manifest)
    print("  explication IA :\n" + "\n".join("    " + l for l in explanation.splitlines()))

    url = open_pull_request(repo, sha, fixed_yaml, explanation, summary)
    print(f"\n  ✅ Pull Request : {url}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"ERREUR: {exc}", file=sys.stderr)
        sys.exit(1)
