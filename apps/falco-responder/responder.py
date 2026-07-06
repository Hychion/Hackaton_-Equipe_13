#!/usr/bin/env python3
"""
Falco AI Responder — Hackathon OVHcloud × Ynov (équipe 13) — chantier B
======================================================================
Étend l'IA à la couche RUNTIME : Falco détecte un comportement suspect
(shell dans un conteneur, lecture de /etc/shadow…) → falcosidekick POST
l'événement ici → l'IA (OVH AI Endpoints) analyse l'incident → une issue
GitHub est ouverte avec l'analyse + les recommandations.

Reçoit des événements Falco au format falcosidekick (JSON) sur POST /.

Config (env) :
  OVH_AI_BASE_URL, FALCO_AI_MODEL, OVH_AI_TOKEN   (IA — token via ESO)
  GITHUB_TOKEN (via ESO), GITHUB_REPO
  MIN_PRIORITY  (défaut: warning)
"""
import os
import threading

from flask import Flask, request
from openai import OpenAI
from github import Github, Auth

OVH_AI_BASE_URL = os.environ["OVH_AI_BASE_URL"]
AI_MODEL = os.environ.get("FALCO_AI_MODEL", "gpt-oss-120b")
OVH_AI_TOKEN = os.environ["OVH_AI_TOKEN"]
GITHUB_REPO = os.environ["GITHUB_REPO"]
MIN_PRIORITY = os.environ.get("MIN_PRIORITY", "warning").lower()

# Échelle de priorité Falco (syslog)
LEVELS = ["debug", "informational", "notice", "warning",
          "error", "critical", "alert", "emergency"]

app = Flask(__name__)
ai = OpenAI(base_url=OVH_AI_BASE_URL, api_key=OVH_AI_TOKEN,
            timeout=120.0, max_retries=2)
repo = Github(auth=Auth.Token(os.environ["GITHUB_TOKEN"])).get_repo(GITHUB_REPO)

# Anti-spam : une issue par règle Falco (en mémoire, suffisant pour la démo)
_seen = set()
_lock = threading.Lock()

SYSTEM_PROMPT = """Tu es analyste SOC (sécurité runtime Kubernetes).
On te donne un événement de sécurité détecté par Falco. Produis une analyse
concise en français :
- Ce qu'il s'est passé (en clair) ;
- Le risque / la gravité et le vecteur d'attaque probable ;
- 2 à 4 recommandations de remédiation concrètes (config K8s, policy Kyverno…).
Sois factuel et actionnable, pas de blabla."""


def priority_ok(priority: str) -> bool:
    p = (priority or "").lower()
    return p in LEVELS and LEVELS.index(p) >= LEVELS.index(MIN_PRIORITY)


def analyze_and_report(event: dict):
    rule = event.get("rule", "règle inconnue")
    with _lock:
        if rule in _seen:
            return
        _seen.add(rule)

    output = event.get("output", "")
    fields = event.get("output_fields", {})
    priority = event.get("priority", "?")
    details = "\n".join(f"  {k}: {v}" for k, v in fields.items())
    prompt = (f"Règle Falco : {rule}\nPriorité : {priority}\n"
              f"Message : {output}\nChamps :\n{details}")

    try:
        resp = ai.chat.completions.create(
            model=AI_MODEL, temperature=0.2, max_tokens=1500,
            messages=[{"role": "system", "content": SYSTEM_PROMPT},
                      {"role": "user", "content": prompt}],
        )
        analysis = resp.choices[0].message.content.strip()
    except Exception as exc:  # noqa: BLE001
        analysis = f"_(analyse IA indisponible : {exc})_"

    body = (f"## Incident runtime détecté par Falco\n\n"
            f"**Règle :** {rule}\n**Priorité :** {priority}\n\n"
            f"```\n{output}\n```\n\n"
            f"## Analyse IA (OVH AI Endpoints — {AI_MODEL})\n\n{analysis}\n\n"
            f"---\n*Issue générée automatiquement par le falco-responder.*")
    try:
        issue = repo.create_issue(
            title=f"[Falco] {rule}", body=body, labels=["falco", "incident-runtime"])
        print(f"issue créée : {issue.html_url}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"ERREUR création issue : {exc}", flush=True)


@app.post("/")
def webhook():
    event = request.get_json(force=True, silent=True) or {}
    if priority_ok(event.get("priority", "")):
        print(f"alerte Falco reçue : {event.get('rule')} [{event.get('priority')}]", flush=True)
        threading.Thread(target=analyze_and_report, args=(event,), daemon=True).start()
    return "", 200


@app.get("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    print(f"falco-responder prêt (modèle={AI_MODEL}, min_priority={MIN_PRIORITY})", flush=True)
    app.run(host="0.0.0.0", port=8080)
