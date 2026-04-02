#!/usr/bin/env python3
from flask import Flask, request, render_template_string
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DB_FILE = "users_cor.db"

# ====================== BASE DE DONNÉES AVEC HASH ======================
if not os.path.exists(DB_FILE):
    conn = sqlite3.connect(DB_FILE)
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (username TEXT NOT NULL UNIQUE, 
                     password_hash TEXT NOT NULL)''')   # Changement : password_hash

    # Liste des utilisateurs avec mots de passe hashés (sécurisé)
    raw_users = [
        ("mamolava", "nY_toka//_//Ko1"),
        ("izy", "cyber2026@clon/")
    ]

    for username, plain_password in raw_users:
        password_hash = generate_password_hash(plain_password)   # Hashage du mot de passe
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                     (username, password_hash))

    conn.commit()
    conn.close()
    print(f"Base de données '{DB_FILE}' créée avec mots de passe HASHÉS (sécurisé).")

# ====================== TEMPLATE HTML ======================
HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Login - Sujet 2 (Version Sécurisée)</title>
    <style>
        body {font-family: Arial, sans-serif; background:#0f1117; color:#c9d1d9; padding:50px; text-align:center;}
        input, button {padding:12px; margin:10px; width:300px; border-radius:8px; border:none; font-size:16px;}
        input {background:#1f2937; color:white;}
        button {background:#10b981; color:white; font-weight:bold; cursor:pointer;}
        button:hover {background:#34d399;}
        .success {color:#10b981; font-size:18px; margin-top:20px;}
        .info {color:#888; font-size:14px;}
        table {margin:20px auto; border-collapse:collapse; width:60%;}
        th, td {border:1px solid #444; padding:10px; text-align:left;}
        th {background:#1f2937;}
    </style>
</head>
<body>
    <h1> Login (Version Sécurisée)</h1>
    <p class="info">Base : users.db — Mots de passe HASHÉS (non visibles en clair)</p>
    
    <form method="POST">
        <input type="text" name="username" placeholder="Nom d'utilisateur" required><br>
        <input type="password" name="password" placeholder="Mot de passe" required><br>
        <button type="submit">Se connecter</button>
    </form>

    {% if message %}
        <p class="success">{{ message | safe }}</p>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        try:
            conn = sqlite3.connect(DB_FILE)
            
            # ================================================
            # CODE VULNÉRABLE (Avant correction)
            # ================================================
            """
            query = f"SELECT username, password FROM users WHERE username='{username}' AND password='{password}'"
            results = conn.execute(query).fetchall()
            """

            # ================================================
            # CODE CORRIGÉ ET SÉCURISÉ 
            # ================================================
            # On utilise des paramètres (?) au lieu de concaténer les chaînes
            # Cela empêche l'injection SQL
            query = "SELECT username, password_hash FROM users WHERE username=?"
            result = conn.execute(query, (username,)).fetchone()
            conn.close()

            if result:
                stored_username, stored_hash = result
                # Vérification sécurisée du mot de passe
                if check_password_hash(stored_hash, password):
                    message = f"Connexion réussie !<br>Bienvenue <b>{stored_username}</b>"
                else:
                    message = " Mot de passe incorrect"
            else:
                message = " Nom d'utilisateur incorrect"
                
        except Exception as e:
            message = f"Erreur serveur"

    return render_template_string(HTML, message=message)


if __name__ == '__main__':
    print(" Application Flask SÉCURISÉE démarrée → http://127.0.0.1:5000")
    print("   Mots de passe hashés + protection contre SQL Injection")
    app.run(host='0.0.0.0', port=5000, debug=False)
