# CyberSec Tool — Sujet 2 : Gestion des Vulnérabilités
**Groupe 7 | FANA| Python 3 / PyQt5 | Kali Linux**

---

## Description

Application de bureau développée en Python 3 avec PyQt5 pour Kali Linux et Ubuntu.  
Elle guide l'utilisateur à travers le **cycle complet de gestion des vulnérabilités**  
tel qu'enseigné dans le cours, en appliquant chaque étape de manière structurée  
sur une cible réseau réelle.

---

## But

Démontrer concrètement comment **analyser, classifier, évaluer, documenter,  
corriger et vérifier** les vulnérabilités d'un système cible en suivant  
le cycle académique :

```
Découvrir → Classifier → Évaluer → Rapporter → Corriger → Vérifier
```

---

## Fonctionnalités

| Fonctionnalité          | Description                                                    |
|-------------------------|----------------------------------------------------------------|
| 6 onglets indépendants  | Un onglet par étape du cycle                                   |
| Terminal intégré        | Sortie des outils en temps réel avec coloration                |
| Tableaux de résultats   | Ports, services, vulnérabilités et actions affichés proprement |
| Badge de statut         | EN ATTENTE · EN COURS · TERMINÉ · ERREUR                       |
| Génération PDF          | Rapport complet structuré par étape et par cible               |
| Compteur global         | X / 6 étapes réalisées mis à jour automatiquement              |
| Validation de cible     | Vérifie l'IP ou l'URL avant tout lancement                     |

---

## Outils utilisés

| Outil          | Rôle                        | But dans le projet                                          |
|----------------|-----------------------------|-------------------------------------------------------------|
| **Nmap**       | Scanner réseau              | Découvrir les ports ouverts, services et versions           |
| **Nikto**      | Scanner web                 | Détecter les vulnérabilités HTTP et configurations faibles  |
| **Nmap NSE**   | Scripts de vulnérabilités   | Identifier des CVE via `--script vuln`                      |
| **WhatWeb**    | Fingerprinting web          | Identifier les technologies et versions du serveur          |
| **OpenVAS/GVM**| Scanner complet             | Scan approfondi avec scoring CVSS                           |
| **PyQt5**      | Interface graphique         | Fenêtre, onglets et composants visuels                      |
| **ReportLab**  | Génération PDF              | Rapport PDF structuré avec tableaux et sections             |

Tous les outils sont **gratuits et open source**, disponibles sur Kali Linux.

---

## Installation

```bash
# Outils réseau
sudo apt update
sudo apt install nmap nikto whatweb gvm python3-pyqt5

# Dépendance Python
pip install reportlab --break-system-packages
```

---

## Lancement

```bash
python3 app.py
```

Entrer l'adresse IP ou l'URL de la cible dans la barre du haut, puis suivre  
les onglets dans l'ordre de 1 à 6.

---

## Étapes de démo — Cycle complet

---

### Étape 1 — Découvrir

**Onglet :** `1. Découvrir`  
**Bouton :** `Lancer le scan`  
**Commande exécutée :**
```bash
nmap -sV --open -T4 <IP_CIBLE>
```
**But :** Identifier tous les ports ouverts et les services qui tournent sur la cible.

**Résultat obtenu sur notre cible (192.168.43.111) :**
```
PORT     STATE  SERVICE  VERSION
8080/tcp open   http     Jetty 12.0.22
```
Le tableau de l'onglet se remplit automatiquement avec les ports détectés.

---

### Étape 2 — Classifier

**Onglet :** `2. Classifier`  
**Bouton :** `Classifier les actifs`  
**Commande exécutée :**
```bash
nmap -sV --open -T4 <IP_CIBLE>
```
**But :** Attribuer un niveau de criticité à chaque actif découvert.

| Niveau  | Critères                                              |
|---------|-------------------------------------------------------|
| HAUTE   | Ports critiques : FTP, Telnet, RDP, SMB, MySQL, HTTP  |
| MOYENNE | Services exposés : SSH, DNS, SMTP, IMAP               |
| FAIBLE  | Autres services non critiques                         |

**Résultat obtenu :**
```
8080/tcp   http   Jetty 12.0.22   MOYENNE
```
Port 8080 classé MOYENNE — serveur web alternatif, exposé mais non critique.

---

### Étape 3 — Évaluer

**Onglet :** `3. Évaluer`  
**Bouton :** `Nikto` ou `Nmap NSE`  
**Commande exécutée (Nikto) :**
```bash
nikto -h http://192.168.43.111:8080
```
**But :** Détecter les vulnérabilités web — headers manquants, CVE, configurations faibles.

**Résultats obtenus :**
```
MOYENNE   X-Frame-Options absent         → risque Clickjacking
MOYENNE   X-Content-Type-Options absent  → risque MIME sniffing
INFO      Jenkins 2.516.1 identifié via les headers HTTP
INFO      Header x-hudson présent (ancienne version Jenkins 1.395)
INFO      Clé RSA publique exposée dans x-instance-identity
INFO      Répertoires CGI accessibles
```
Observation : la cible fait tourner **Jenkins 2.516.1** sur Jetty — outil CI/CD  
très ciblé par les attaquants si mal configuré.

---

### Étape 4 — Rapporter

**Onglet :** `4. Rapporter`  
**Bouton :** `Générer le rapport PDF`  
**But :** Compiler tous les résultats des étapes précédentes dans un rapport PDF  
structuré, sauvegardé dans `~/CyberSec_Rapports/`.

**Contenu du rapport PDF généré :**

| Section               | Contenu                                              |
|-----------------------|------------------------------------------------------|
| Page de couverture    | Cible, date, groupe, outil                           |
| Résumé du cycle       | Tableau des 6 étapes — Réalisé / Non exécuté         |
| Section 1 Découvrir   | Tableau des ports ouverts détectés                   |
| Section 2 Classifier  | Tableau avec niveaux de criticité par actif          |
| Section 3 Évaluer     | Tableau des vulnérabilités avec sévérité et CVE      |
| Section 4 Rapporter   | Description narrative de l'audit                     |
| Section 5 Corriger    | Plan de remédiation priorisé CRITIQUE → FAIBLE       |
| Section 6 Vérifier    | Résultats du rescan de confirmation                  |

Cliquer sur `Ouvrir le PDF` pour le visualiser directement.

---

### Étape 5 — Corriger

**Onglet :** `5. Corriger`  
**Bouton :** `Charger les actions de remédiation`  
**But :** Générer automatiquement un plan d'action priorisé  
à partir des résultats des étapes 2 et 3.

**Actions générées pour notre cible :**
```
MOYENNE   Ajouter X-Frame-Options: SAMEORIGIN dans la config Jetty
MOYENNE   Ajouter X-Content-Type-Options: nosniff
MOYENNE   Masquer les headers x-jenkins et x-hudson (information disclosure)
FAIBLE    Vérifier les droits d'accès aux répertoires CGI
```

---

### Étape 6 — Vérifier

**Onglet :** `6. Vérifier`  
**Bouton :** `Rescanner la cible`  
**Commande exécutée :**
```bash
nmap -sV --open -T4 <IP_CIBLE>
```
**But :** Confirmer que les corrections ont été appliquées et que  
la surface d'attaque n'a pas augmenté.

**Résultat attendu après correction :**
```
Port encore ouvert     →  Encore ouvert  (affiché en orange)
Aucun port détecté     →  ✔ OK — surface d'attaque réduite  (affiché en vert)
```

---

## Résumé du cycle appliqué sur la cible 192.168.43.111

| Étape      | Action réalisée                        | Résultat                          |
|------------|----------------------------------------|-----------------------------------|
| Découvrir  | nmap -sV --open                        | Port 8080 ouvert — Jetty 12.0.22  |
| Classifier | Analyse criticité                      | Niveau MOYENNE                    |
| Évaluer    | nikto -h http://192.168.43.111:8080    | 2 headers manquants, Jenkins expo |
| Rapporter  | Génération PDF                         | Rapport sauvegardé                |
| Corriger   | Plan de remédiation chargé             | 4 actions identifiées             |
| Vérifier   | Rescan nmap                            | Confirmation de l'état final      |

---

## Configuration requise

```
Système     : Kali Linux ou Ubuntu 20.04+
Python      : 3.8 ou supérieur
Paquets     : nmap, nikto, whatweb, gvm, python3-pyqt5
              pip : reportlab
Réseau      : Accès réseau à la cible (même LAN ou VM en bridge)
```

---

## Structure du projet

```
G_Vulnera/
├── app.py          Application principale (6 onglets + génération PDF)
└── README.md       Ce fichier
```

---

*CyberSec Tool — FANA | Groupe 7 | Sujet 2 — Gestion de vulnérabilité*
