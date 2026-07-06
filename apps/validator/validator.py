#!/usr/bin/env python3
"""
Validateur pré-prod — Hackathon OVHcloud × Ynov (équipe 13)
===========================================================
Le SAS de validation : avant de promouvoir un correctif en prod, on le teste
en pré-prod et on PUBLIE les résultats dans Grafana (never trust, always verify).

Boucle continue :
  1. Santé   : le workload pré-prod a-t-il tous ses pods Ready ?
  2. Smoke   : le service répond-il HTTP 200 ?
  3. CVE     : le rapport Trivy a-t-il un nb de CRITICAL <= seuil ?
  4. Policy  : le workload passe-t-il les policies Kyverno (0 violation) ?
  → expose des métriques Prometheus (scrappées par Prometheus → Grafana)
  → si TOUT est vert : ouvre une PR de promotion pré-prod → prod (le gate).

Config (env) :
  PREPROD_NAMESPACE (def: preprod), WORKLOAD (def: vulnerable-web)
  SERVICE_URL (smoke test), CVE_CRITICAL_MAX (def: 20)
  CHECK_INTERVAL (def: 30s), METRICS_PORT (def: 9099)
  Promotion (optionnelle) : GITHUB_TOKEN, GITHUB_REPO,
    PREPROD_PATH, PROD_PATH, PROMOTE=true|false
"""
import os
import time
import urllib.request

from kubernetes import client, config
from prometheus_client import Gauge, start_http_server

PREPROD_NS = os.environ.get("PREPROD_NAMESPACE", "preprod")
WORKLOAD = os.environ.get("WORKLOAD", "vulnerable-web")
SERVICE_URL = os.environ.get("SERVICE_URL", f"http://{WORKLOAD}.{PREPROD_NS}.svc:8080/")
CVE_CRITICAL_MAX = int(os.environ.get("CVE_CRITICAL_MAX", "20"))
INTERVAL = int(os.environ.get("CHECK_INTERVAL", "30"))
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9099"))
PROMOTE = os.environ.get("PROMOTE", "false").lower() == "true"

# --- Métriques exposées à Prometheus ---
G_STATUS = Gauge("preprod_validation_passed", "1 si toute la validation pré-prod passe")
G_CHECK = Gauge("preprod_validation_check", "1=pass 0=fail par contrôle", ["check"])
G_CVE = Gauge("preprod_cve_count", "CVE du workload pré-prod (Trivy)", ["severity"])
G_VIOL = Gauge("preprod_policy_violations", "Violations Kyverno du workload pré-prod")
G_READY = Gauge("preprod_ready_to_promote", "1 si le correctif peut être promu en prod")


def k8s():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def check_health(core) -> bool:
    pods = core.list_namespaced_pod(PREPROD_NS, label_selector=f"app={WORKLOAD}").items
    if not pods:
        return False
    return all(
        any(c.type == "Ready" and c.status == "True" for c in (p.status.conditions or []))
        for p in pods
    )


def check_smoke() -> bool:
    try:
        with urllib.request.urlopen(SERVICE_URL, timeout=5) as r:
            return 200 <= r.status < 400
    except Exception:  # noqa: BLE001
        return False


def check_cve(custom) -> tuple[bool, int, int]:
    crit = high = 0
    try:
        reports = custom.list_namespaced_custom_object(
            "aquasecurity.github.io", "v1alpha1", PREPROD_NS, "vulnerabilityreports")["items"]
        for r in reports:
            s = r.get("report", {}).get("summary", {})
            crit += s.get("criticalCount", 0)
            high += s.get("highCount", 0)
    except client.ApiException:
        return False, 0, 0
    return crit <= CVE_CRITICAL_MAX, crit, high


def check_policy(custom) -> tuple[bool, int]:
    fails = 0
    try:
        reports = custom.list_namespaced_custom_object(
            "wgpolicyk8s.io", "v1alpha2", PREPROD_NS, "policyreports")["items"]
        for r in reports:
            for res in r.get("results", []):
                if res.get("result") == "fail":
                    fails += 1
    except client.ApiException:
        return True, 0  # pas de rapport = pas de violation connue
    return fails == 0, fails


def promote_if_green():
    """Ouvre une PR de promotion pré-prod → prod (le gate humain reste le merge)."""
    from github import Github, Auth
    repo = Github(auth=Auth.Token(os.environ["GITHUB_TOKEN"])).get_repo(os.environ["GITHUB_REPO"])
    preprod_path, prod_path = os.environ["PREPROD_PATH"], os.environ["PROD_PATH"]
    branch = "promote/preprod-to-prod"
    src = repo.get_contents(preprod_path, ref="main")
    try:
        dst_sha = repo.get_contents(prod_path, ref="main").sha
    except Exception:  # noqa: BLE001
        dst_sha = None
    if dst_sha and repo.get_contents(prod_path, ref="main").decoded_content == src.decoded_content:
        return  # déjà identique, rien à promouvoir
    for pr in repo.get_pulls(state="open"):
        if pr.head.ref == branch:
            return  # promotion déjà en cours
    main = repo.get_branch("main")
    try:
        repo.get_git_ref(f"heads/{branch}").delete()
    except Exception:  # noqa: BLE001
        pass
    repo.create_git_ref(ref=f"refs/heads/{branch}", sha=main.commit.sha)
    kw = dict(path=prod_path, message="promote(preprod->prod): correctif validé en pré-prod",
              content=src.decoded_content, branch=branch)
    if dst_sha:
        repo.update_file(sha=dst_sha, **kw)
    else:
        repo.create_file(**kw)
    repo.create_pull(
        title="[Promotion] Correctif validé en pré-prod → prod",
        body="La validation pré-prod est **verte** (santé, smoke, CVE, policies). "
             "Promotion du correctif vers la prod. *Merge = décision humaine.*",
        head=branch, base="main")
    print("PR de promotion ouverte", flush=True)


def main():
    k8s()
    core, custom = client.CoreV1Api(), client.CustomObjectsApi()
    start_http_server(METRICS_PORT)
    print(f"validateur pré-prod actif (ns={PREPROD_NS}, port={METRICS_PORT})", flush=True)
    while True:
        health = check_health(core)
        smoke = check_smoke()
        cve_ok, crit, high = check_cve(custom)
        pol_ok, viol = check_policy(custom)
        passed = health and smoke and cve_ok and pol_ok

        G_CHECK.labels("health").set(int(health))
        G_CHECK.labels("smoke").set(int(smoke))
        G_CHECK.labels("cve").set(int(cve_ok))
        G_CHECK.labels("policy").set(int(pol_ok))
        G_CVE.labels("critical").set(crit)
        G_CVE.labels("high").set(high)
        G_VIOL.set(viol)
        G_STATUS.set(int(passed))
        G_READY.set(int(passed))
        print(f"validation: health={health} smoke={smoke} cve={cve_ok}({crit}c) "
              f"policy={pol_ok}({viol}) => {'VERT' if passed else 'ROUGE'}", flush=True)

        if passed and PROMOTE:
            try:
                promote_if_green()
            except Exception as exc:  # noqa: BLE001
                print(f"promotion impossible: {exc}", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
