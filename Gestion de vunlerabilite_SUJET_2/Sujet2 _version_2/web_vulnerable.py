#!/usr/bin/env python3
from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)
DB_FILE = "users.db"

# ====================== BASE DE DONNÉES ======================
if not os.path.exists(DB_FILE):
    conn = sqlite3.connect(DB_FILE)
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (username TEXT NOT NULL UNIQUE, 
                     password TEXT NOT NULL)''')
    
    users = [
        ("mamolava", "nY_toka//_//Ko1"),
        ("izy", "cyber2026@clon/")
    ]
    
    conn.executemany("INSERT INTO users VALUES (?, ?)", users)
    conn.commit()
    conn.close()
    print(f"Base de données '{DB_FILE}' créée avec {len(users)} utilisateurs.")

# ====================== TEMPLATE HTML ======================
HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Login Vulnérable - Sujet 2</title>
    <style>
        body {
            font-family: Arial, sans-serif; 
            background: #0f1117; 
            color: #c9d1d9; 
            padding: 50px; 
            text-align: center;
        }
        input, button {
            padding: 12px; 
            margin: 10px; 
            width: 300px; 
            border-radius: 8px; 
            border: none; 
            font-size: 16px;
        }
        input {
            background: #1f2937; 
            color: white;
        }
        button {
            background: #ef4444; 
            color: white; 
            font-weight: bold; 
            cursor: pointer;
        }
        button:hover {
            background: #f87171;
        }
        .success {
            color: #10b981; 
            font-size: 18px;
            margin-top: 20px;
        }
        .info {
            color: #888; 
            font-size: 14px;
        }
        table {
            margin: 20px auto;
            border-collapse: collapse;
            width: 60%;
        }
        th, td {
            border: 1px solid #444;
            padding: 10px;
            text-align: left;
        }
        th {
            background: #1f2937;
        }
    </style>
</head>
<body>
    <h1>Login Vulnérable (SQL Injection)</h1>
    <p class="info">Base : users.db — username + password (non chiffré)</p>
    
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
            
            # VERSION VULNÉRABLE (pour la démonstration)
            query = f"SELECT username, password FROM users WHERE username='{username}' AND password='{password}'"
            results = conn.execute(query).fetchall()   # fetchall() pour récupérer tous les résultats
            conn.close()

            if results:
                if len(results) == 1:
                    user, pwd = results[0]
                    message = f"Connexion réussie !<br>Bienvenue <b>{user}</b><br>Mot de passe : {pwd}"
                else:
                    # Affichage tableau quand plusieurs utilisateurs sont retournés (Injection SQL)
                    message = "<h3>Injection SQL réussie ! Voici tous les utilisateurs trouvés :</h3><br>"
                    message += "<table>"
                    message += "<tr><th>Utilisateur</th><th>Mot de passe</th></tr>"
                    for user, pwd in results:
                        message += f"<tr><td>{user}</td><td>{pwd}</td></tr>"
                    message += "</table>"
            else:
                message = "Nom d'utilisateur ou mot de passe incorrect"
                
        except Exception as e:
            message = f"Erreur serveur : {str(e)}"

    return render_template_string(HTML, message=message)


if __name__ == '__main__':
    print("Application Flask vulnérable démarrée → http://127.0.0.1:5000")
    print("Utilisez ce lien pour tester l'attaque SQL Injection")
    app.run(host='0.0.0.0', port=5000, debug=False)
