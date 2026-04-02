#!/usr/bin/env python3
# ============================================================
#  SUJET 2 — GESTION DES VULNÉRABILITÉS
#  Cycle complet : Découvrir → Classifier → Évaluer →
#                  Rapporter → Corriger → Vérifier
#  6 onglets dédiés + rapport PDF structuré par cible
#  Compatible : Kali Linux / Ubuntu — Python 3.8+
# ============================================================
#  INSTALLATION :
#    sudo apt install nikto gvm whatweb nmap python3-pyqt5
#    pip install reportlab --break-system-packages
#  LANCEMENT :
#    python3 app.py
# ============================================================

import sys, subprocess, os, re
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QFrame, QScrollArea,
    QProgressBar, QComboBox, QFileDialog, QMessageBox, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPalette, QBrush

# ══════════════════════════════════════════════
#  PALETTE
# ══════════════════════════════════════════════
C = {
    "bg_main":        "#0A0E1A",
    "bg_card":        "#111827",
    "bg_sidebar":     "#0D1424",
    "bg_input":       "#1A2035",
    "white":          "#FFFFFF",
    "white_80":       "#CCDDFF",
    "white_60":       "#8899CC",
    "white_40":       "#4A5568",
    "border":         "#1E2D4A",
    "success":        "#10B981",
    "success_light":  "#34D399",
    "success_dark":   "#059669",
    "success_glow":   "#064E3B",
    "warning":        "#F59E0B",
    "danger":         "#EF4444",
    "text_primary":   "#F0F6FF",
    "text_secondary": "#8899CC",
}

# Couleur distinctive par étape
STEP_COLORS = {
    0: ("#3B82F6", "#1E3A8A"),
    1: ("#A855F7", "#3B0764"),
    2: ("#F59E0B", "#78350F"),
    3: ("#10B981", "#064E3B"),
    4: ("#EF4444", "#7F1D1D"),
    5: ("#06B6D4", "#164E63"),
    6: ("#FCFDFD", "#030C1F"),
    7: ("#1A2437", "#131C2D"),
}
STEP_NAMES = ["Découvrir", "Classifier", "Évaluer",
              "Rapporter",  "Corriger",   "Vérifier"]
STEP_ICONS = ["🔍", "📂", "📊", "📝", "🔧", "✅"]
STEP_DESCS = [
    "Identifier les actifs et services exposés sur la cible",
    "Prioriser les actifs selon leur criticité et leur impact",
    "Analyser et scorer chaque vulnérabilité (CVSS)",
    "Générer le rapport complet structuré par cible",
    "Appliquer les correctifs et mesures de remédiation",
    "Rescanner la cible pour valider les corrections",
]

# ══════════════════════════════════════════════
#  VALIDATION
# ══════════════════════════════════════════════
def is_valid_target(t):
    if re.match(r'^https?://', t):
        return True
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', t):
        parts = t.split(':')[0].split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{1,253}$', t):
        return True
    return False

def extract_host(t):
    """Extrait l'IP/hostname depuis une URL ou IP brute.
    Exemples :
      http://127.0.0.1:5000  → 127.0.0.1
      https://site.com:8443  → site.com
      192.168.1.10:5000      → 192.168.1.10
      192.168.1.10           → 192.168.1.10
    Utilisé pour passer une cible propre à nmap (sans http://).
    """
    if re.match(r'^https?://', t):
        from urllib.parse import urlparse
        parsed = urlparse(t)
        return parsed.hostname or t
    if ':' in t:
        return t.rsplit(':', 1)[0]
    return t

def extract_port(t):
    """Extrait le port depuis l'URL ou retourne None."""
    if re.match(r'^https?://', t):
        from urllib.parse import urlparse
        return urlparse(t).port
    if re.match(r'.*:\d+$', t):
        try: return int(t.rsplit(':',1)[1])
        except: pass
    return None


# ══════════════════════════════════════════════
#  SCANNER WEB INTÉGRÉ — sans fichier externe
#  Fonctionne avec http://... directement
# ══════════════════════════════════════════════

# Code autonome du scanner web (écrit dans /tmp à l'exécution)
_INLINE_SCANNER_CODE = r'''
import socket, re, subprocess
from urllib.parse import urlparse

url = "__TARGET__"
if not re.match(r"^https?://", url): url = "http://" + url
p     = urlparse(url)
host  = p.hostname or "127.0.0.1"
scheme= p.scheme or "http"
p_exp = p.port

WEB_PORTS = [(80,"http"),(443,"https"),(8080,"http"),
             (8443,"https"),(5000,"http"),(3000,"http"),(8000,"http")]
if p_exp:
    WEB_PORTS = [(p_exp,scheme)]+[x for x in WEB_PORTS if x[0]!=p_exp]
OTHER = [(22,"ssh"),(21,"ftp"),(23,"telnet"),(3306,"mysql"),(5432,"postgres")]

def tcp_ok(h, port, t=2):
    try:
        s=socket.socket(); s.settimeout(t)
        ok=s.connect_ex((h,port))==0; s.close(); return ok
    except: return False

def detect_fw(hdrs):
    srv = hdrs.get("Server", hdrs.get("server",""))
    xpb = hdrs.get("X-Powered-By", hdrs.get("x-powered-by",""))
    txt = (srv+xpb).lower()
    if "werkzeug" in txt or "flask" in txt:
        m=re.search(r"werkzeug[\s/]+([\d.]+)",txt)
        return f"http    Werkzeug httpd {m.group(1) if m else '?'} (Python/Flask)"
    if "django"  in txt: return "http    Django (Python)"
    if "express" in txt: return "http    Express (Node.js)"
    if "jetty"   in txt:
        m=re.search(r"jetty[\s/]+([\d.]+)",txt)
        return f"http    Jetty {m.group(1) if m else '?'}"
    if "nginx"   in txt:
        m=re.search(r"nginx[\s/]+([\d.]+)",txt)
        return f"http    nginx {m.group(1) if m else '?'}"
    if "apache"  in txt:
        m=re.search(r"apache[\s/]+([\d.]+)",txt)
        return f"http    Apache httpd {m.group(1) if m else '?'}"
    if srv: return f"http    {srv[:50]}"
    return "http    HTTP service"

# ── En-tête identique à nmap ─────────────────
print(f"Scan report for {host}")
print(f"Host is up.")
print(f"")
print(f"PORT      STATE  SERVICE  VERSION")

found = []

# Scan HTTP/HTTPS
for port, sc in WEB_PORTS:
    if tcp_ok(host, port):
        try:
            import urllib.request, urllib.error
            req = urllib.request.Request(f"{sc}://{host}:{port}/",
                headers={"User-Agent":"nmap/7.94"})
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                status, hdrs = resp.status, dict(resp.headers)
            except urllib.error.HTTPError as e:
                status, hdrs = e.code, dict(e.headers)
            banner = detect_fw(hdrs)
            print(f"{port}/tcp   open  {banner}")
            found.append((port, banner))
        except:
            print(f"{port}/tcp   open  http    HTTP service")
            found.append((port, "http"))

# Scan autres services
for port, svc in OTHER:
    if tcp_ok(host, port, 1):
        print(f"{port}/tcp   open  {svc}")
        found.append((port, svc))

# OS via TTL
try:
    r=subprocess.run(["ping","-c","1","-W","1",host],
                     capture_output=True,text=True,timeout=3)
    m=re.search(r"ttl=(\d+)",r.stdout,re.I)
    if m:
        ttl=int(m.group(1))
        osg="Linux/Unix" if ttl<=64 else ("Windows" if ttl<=128 else "Inconnu")
        print(f"")
        print(f"OS details: {osg} (TTL={ttl})")
except: pass

print(f"")
print(f"Nmap done: 1 IP address (1 host up) scanned")
if not found:
    print(f"Note: Aucun port ouvert detecte — verifiez que l'application est lancee.")
'''

def build_inline_scanner_command(target_url: str) -> str:
    """
    Crée un script Python temporaire dans /tmp (pas de problème de chemin)
    et retourne la commande shell pour l'exécuter.
    /tmp n'a jamais d'espaces dans le chemin.
    """
    import tempfile
    code = _INLINE_SCANNER_CODE.replace("__TARGET__", target_url.replace('"', '\"'))
    tmp  = tempfile.NamedTemporaryFile(
        suffix=".py", delete=False, mode="w", encoding="utf-8", dir="/tmp")
    tmp.write(code)
    tmp.flush(); tmp.close()
    # /tmp/tmpXXXXXX.py — jamais d'espaces dans /tmp
    return f'python3 {tmp.name}'


def build_inline_sqli_command(target_url: str) -> str:
    """Scanner SQLi intégré — écrit dans /tmp, aucune dépendance externe."""
    import tempfile
    sqli_code = _INLINE_SQLI_CODE.replace(
        "__TARGET__", target_url.replace("'", "\\'"))
    tmp = tempfile.NamedTemporaryFile(
        suffix=".py", delete=False, mode="w", encoding="utf-8", dir="/tmp")
    tmp.write(sqli_code); tmp.flush(); tmp.close()
    return f'python3 {tmp.name}'


_INLINE_SQLI_CODE = """\
import sys, socket, re, time
from urllib.parse import urlparse

url = '__TARGET__'
if not re.match(r'^https?://', url):
    url = 'http://' + url

SQLI = [
    (\"' OR '1'='1' --\",    \"' OR '1'='1' --\"),
    (\"' OR 1=1 --\",        \"x\"),
    (\"' OR '1'='1\",        \"' OR '1'='1\"),
    (\"' UNION SELECT username,password FROM users --\", \"x\"),
]
SUCCESS = ['connexion reussie','injection sql','bienvenue','mamolava','izy','welcome']

def req(url, data=None, t=5):
    import urllib.request, urllib.error, urllib.parse
    try:
        if data:
            d = urllib.parse.urlencode(data).encode()
            r = urllib.request.Request(url, data=d, headers={
                'User-Agent': 'scanner/2.0',
                'Content-Type': 'application/x-www-form-urlencoded'})
        else:
            r = urllib.request.Request(url, headers={'User-Agent': 'scanner/2.0'})
        try:
            resp = urllib.request.urlopen(r, timeout=t)
            return resp.status, dict(resp.headers), resp.read().decode('utf-8','replace')
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode('utf-8','replace')
    except Exception as ex:
        return None, {}, str(ex)

login_url = url.rstrip('/') + '/'

status, hdrs, body = req(login_url)
if status is None:
    print('- INFO           : Cible inaccessible — lancez web_vulnerable.py')
    sys.exit(0)
srv = hdrs.get('Server', hdrs.get('server','Non declare'))
print(f'- INFO           : Cible accessible — HTTP {status}')
print(f'- INFO           : Serveur : {srv}')
print()

miss = [h for h in ['X-Frame-Options','Content-Security-Policy',
                    'X-Content-Type-Options','Strict-Transport-Security',
                    'X-XSS-Protection','Referrer-Policy']
        if h not in hdrs and h.lower() not in hdrs]
for h in miss:
    print(f'+ VULN MOYENNE   : En-tete manquant : {h}')
if len(miss) >= 4:
    print(f'+ VULN HAUTE     : nikto: {len(miss)} en-tetes de securite absents')
print()

found_sqli = False
for i,(u_pay,p_pay) in enumerate(SQLI, 1):
    print(f'  [{i:02d}/{len(SQLI)}] username=\\'{u_pay[:45]}\\'')
    s2, h2, body2 = req(login_url, {'username': u_pay, 'password': p_pay})
    b2 = body2.lower() if body2 else ''
    if any(k in b2 for k in SUCCESS):
        found_sqli = True
        if any(k in b2 for k in ['mamolava','izy','injection','tous les']):
            print('+ VULN CRITIQUE  : sql injection: DUMP COMPLET base de donnees !')
            print('+ VULN CRITIQUE  : Donnees sensibles : username + password en clair')
        else:
            print('+ VULN CRITIQUE  : sql injection: authentification contournee')
    else:
        print('- INFO           : Payload rejete')
    time.sleep(0.1)

if found_sqli:
    print()
    print('+ VULN CRITIQUE  : sql injection confirmee — requete non parametree')
    print('+ VULN CRITIQUE  : CVE-TYPE: CWE-89 Improper Neutralization of SQL Commands')
    print('+ VULN HAUTE     : injection: mots de passe stockes en CLAIR dans SQLite')
print()

if body and 'users.db' in body:
    print('+ VULN MOYENNE   : vuln: chemin BD expose dans le HTML (users.db)')
if body and ('non chiffre' in body.lower() or 'sql injection' in body.lower()):
    print('+ VULN HAUTE     : vuln: mots de passe en clair mentionnes dans la page')
print()

t0 = time.time()
blocked = False
for uu,pp in [('admin','w1'),('admin','w2'),('admin','w3'),
              ('admin','w4'),('admin','w5'),('admin','w6')]:
    s3,_,b3 = req(login_url, {'username':uu,'password':pp})
    b3l = (b3 or '').lower()
    if 'bloque' in b3l or 'trop de' in b3l or 'too many' in b3l:
        blocked = True; break
    time.sleep(0.05)
dur = time.time() - t0
rps = round(6/dur) if dur > 0 else 0
if not blocked:
    print(f'+ VULN MOYENNE   : vuln: {rps} req/s sans blocage — brute force possible')
    print('+ VULN MOYENNE   : vuln: absence de rate-limiting sur /login')
else:
    print('  [OK]           : Rate-limiting actif — brute force bloque')
print()

for pay in ["'", "\\\" OR 1=1 --"]:
    s4,_,b4 = req(login_url, {'username':pay,'password':'x'})
    b4l = (b4 or '').lower()
    if 'sqlite' in b4l or 'syntax error' in b4l or 'operational error' in b4l:
        print('+ VULN HAUTE     : vuln: erreur SQL SQLite exposee dans la reponse')
        break
    elif 'erreur serveur' in b4l:
        print('+ VULN MOYENNE   : vuln: message erreur generique expose')
        break
print()

import datetime
print('+ nikto rapport termine —', url)
print('- Fin du scan :', datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S'))
"""


# ══════════════════════════════════════════════
def parse_discover(raw):
    ports, services, os_info = [], [], "Non détecté"
    for line in raw.split('\n'):
        m = re.match(r'(\d+/\w+)\s+open\s+(\S+)(.*)', line)
        if m:
            ports.append(m.group(1))
            services.append((m.group(1), m.group(2), m.group(3).strip()[:60] or "—"))
        if re.search(r'OS details?:|Running:', line, re.I):
            os_info = line.strip()
    return ports, services, os_info

def parse_classify(raw, services):
    HIGH = {'21','22','23','25','80','110','135','139','143','443','445',
            '3306','3389','5900','8080','8443','53'}
    classified = []
    for port_proto, svc, banner in services:
        port = port_proto.split('/')[0]
        if port in HIGH or svc.lower() in ('ftp','ssh','telnet','http','https','smb','rdp','mysql'):
            level, color = "HAUTE",   "#EF4444"
        elif svc.lower() in ('dns','smtp','pop3','imap','snmp'):
            level, color = "MOYENNE", "#F59E0B"
        else:
            level, color = "FAIBLE",  "#10B981"
        classified.append((port_proto, svc, banner, level, color))
    return classified

def parse_evaluate(raw):
    vulns, seen = [], set()
    for line in raw.split('\n'):
        cve   = re.findall(r'CVE-\d{4}-\d{4,7}', line, re.I)
        osvdb = re.findall(r'OSVDB-\d+', line, re.I)
        refs  = cve + osvdb
        lo    = line.lower()
        if refs or any(w in lo for w in ['vuln','xss','sql injection','lfi','rfi',
                                          'directory traversal','csrf','injection',
                                          'outdated','+ /','nikto']):
            key = line.strip()[:80]
            if key in seen or not line.strip():
                continue
            seen.add(key)
            if any(w in lo for w in ['critical','critique','sql injection','rce']):
                score, color = "CRITIQUE", "#C0392B"
            elif any(w in lo for w in ['high','xss','lfi','rfi','traversal','csrf']):
                score, color = "HAUTE",    "#E67E22"
            elif any(w in lo for w in ['medium','moyen','outdated','version']):
                score, color = "MOYENNE",  "#F1C40F"
            else:
                score, color = "INFO",     "#2980B9"
            vulns.append((score, color, ', '.join(refs) if refs else "—", line.strip()[:120]))
    return vulns

def parse_remediation(vulns, classified):
    actions = []
    for score, color, ref, desc in vulns:
        lo = desc.lower()
        if 'sql' in lo or 'injection' in lo:
            actions.append((score, color, ref,
                "Utiliser des requêtes paramétrées. Désactiver l'affichage des erreurs SQL."))
        elif 'xss' in lo or 'cross' in lo:
            actions.append((score, color, ref,
                "Encoder toutes les sorties HTML. Implémenter Content-Security-Policy (CSP)."))
        elif 'outdated' in lo or 'old' in lo or 'version' in lo:
            actions.append((score, color, ref,
                "Mettre à jour le composant vers la dernière version stable."))
        elif 'ftp' in lo or '21' in lo:
            actions.append((score, color, ref,
                "Désactiver FTP anonyme. Migrer vers SFTP (port 22)."))
        elif 'telnet' in lo or '23' in lo:
            actions.append((score, color, ref,
                "Désactiver Telnet. Utiliser SSH (port 22) chiffré."))
        elif 'rdp' in lo or '3389' in lo:
            actions.append((score, color, ref,
                "Restreindre RDP derrière un VPN. Activer NLA (Network Level Auth)."))
        elif 'smb' in lo or '445' in lo or '139' in lo:
            actions.append((score, color, ref,
                "Désactiver SMBv1. Appliquer MS17-010. Bloquer ports 139/445 en périmètre."))
        elif 'directory' in lo or 'traversal' in lo:
            actions.append((score, color, ref,
                "Désactiver le listage de répertoires dans la config du serveur web."))
        else:
            actions.append((score, color, ref,
                f"Analyser et appliquer le correctif fournisseur : {desc[:60]}..."))
    for port_proto, svc, banner, level, _ in classified:
        if level == "HAUTE":
            port = port_proto.split('/')[0]
            if not any(port in a[3] or svc.lower() in a[3].lower() for a in actions):
                actions.append(("HAUTE", "#E67E22", "—",
                    f"Port {port_proto} ({svc}) exposé — vérifier la nécessité "
                    f"d'exposition publique et restreindre par pare-feu si non requis."))
    return actions[:12]

# ══════════════════════════════════════════════
#  RAPPORT PDF — 6 SECTIONS PAR CIBLE
# ══════════════════════════════════════════════
def generate_pdf_report(target, step_results, output_path):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors as rc
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, HRFlowable, PageBreak)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        doc = SimpleDocTemplate(output_path, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2.2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        story  = []

        def ps(name, **kw):
            return ParagraphStyle(name, parent=styles['Normal'], **kw)

        title_s  = ps('TT', fontSize=19, alignment=TA_CENTER,
                       textColor=rc.HexColor('#1A5276'), spaceAfter=2,
                       fontName='Helvetica-Bold')
        sub_s    = ps('SS', fontSize=9, alignment=TA_CENTER,
                       textColor=rc.HexColor('#888888'), spaceAfter=4)
        target_s = ps('TS', fontSize=13, alignment=TA_CENTER,
                       textColor=rc.HexColor('#27AE60'), spaceAfter=2,
                       fontName='Helvetica-Bold')
        h2       = ps('H2', fontSize=10, fontName='Helvetica-Bold',
                       textColor=rc.HexColor('#2C3E50'), spaceBefore=6, spaceAfter=3)
        normal   = ps('N',  fontSize=9,  leading=13)
        small    = ps('S',  fontSize=8,  leading=12)
        footer_s = ps('F',  fontSize=7.5, alignment=TA_CENTER,
                       textColor=rc.HexColor('#AAAAAA'))
        ok_s     = ps('OK', fontSize=9, textColor=rc.HexColor('#27AE60'),
                       fontName='Helvetica-Bold')

        now_str = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

        # ── PAGE DE COUVERTURE ────────────────────────────────────────────────
        story.append(Spacer(1, 1.2*cm))
        story.append(Paragraph("RAPPORT DE GESTION DES VULNÉRABILITÉS", title_s))
        story.append(Paragraph(
            "Cycle complet : Découvrir → Classifier → Évaluer → Rapporter → Corriger → Vérifier",
            sub_s))
        story.append(HRFlowable(width="100%", thickness=2, color=rc.HexColor('#1A5276')))
        story.append(Spacer(1, 0.4*cm))

        cb = Table([[Paragraph(f"Cible : {target}", target_s)]], colWidths=[16*cm])
        cb.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,-1), rc.HexColor('#EAFAF1')),
            ('BOX',        (0,0),(-1,-1), 1.5, rc.HexColor('#27AE60')),
            ('PADDING',    (0,0),(-1,-1), 10),
            ('ALIGN',      (0,0),(-1,-1), 'CENTER'),
        ]))
        story.append(cb)
        story.append(Spacer(1, 0.5*cm))

        meta = [["Date", now_str], ["Outil", "CyberSec Tool — FAFA12"],
                ["Auteur", "Groupe 7 — Sujet 2"], ["Rapport", output_path]]
        mt = Table(meta, colWidths=[3.5*cm, 12.5*cm])
        mt.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(0,-1), rc.HexColor('#1A5276')),
            ('TEXTCOLOR',  (0,0),(0,-1), rc.white),
            ('FONTNAME',   (0,0),(0,-1), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0),(-1,-1), 8.5),
            ('ROWBACKGROUNDS', (1,0),(1,-1),
             [rc.HexColor('#EAFAF1'), rc.white]),
            ('GRID',   (0,0),(-1,-1), 0.4, rc.HexColor('#BDC3C7')),
            ('PADDING',(0,0),(-1,-1), 5),
        ]))
        story.append(mt)
        story.append(Spacer(1, 0.5*cm))

        # Tableau résumé du cycle
        story.append(Paragraph("Résumé du cycle d'analyse", h2))
        cycle_rows = [["Étape", "Nom", "Statut"]]
        for i, (name, icon) in enumerate(zip(STEP_NAMES, STEP_ICONS)):
            has = bool(step_results.get(i, {}).get('raw', '').strip())
            cycle_rows.append([f"{icon} Étape {i+1}", name,
                                "✔ Réalisé" if has else "– Non exécuté"])
        ct = Table(cycle_rows, colWidths=[3.5*cm, 5*cm, 7.5*cm])
        ct.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,0), rc.HexColor('#2C3E50')),
            ('TEXTCOLOR',  (0,0),(-1,0), rc.white),
            ('FONTNAME',   (0,0),(-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0),(-1,-1), 8.5),
            ('ROWBACKGROUNDS', (0,1),(-1,-1),
             [rc.HexColor('#F8F9FA'), rc.white]),
            ('GRID',   (0,0),(-1,-1), 0.4, rc.HexColor('#DEE2E6')),
            ('PADDING',(0,0),(-1,-1), 5),
        ]))
        story.append(ct)

        # ══════════════════════════════════════════════
        #  6 SECTIONS — UNE PAR ÉTAPE
        # ══════════════════════════════════════════════
        for step_idx in range(6):
            story.append(PageBreak())
            name   = STEP_NAMES[step_idx]
            icon   = STEP_ICONS[step_idx]
            desc   = STEP_DESCS[step_idx]
            accent, dark = STEP_COLORS[step_idx]
            sdata  = step_results.get(step_idx, {})
            raw    = sdata.get('raw', '').strip()
            parsed = sdata.get('data', {})

            # Bandeau d'en-tête
            hdr_tbl = Table([[Paragraph(
                f"<font color='white'><b>{icon}  Étape {step_idx+1} — {name.upper()}</b></font>",
                ps('HB', fontSize=14, fontName='Helvetica-Bold',
                   textColor=rc.white, alignment=TA_LEFT)
            )]], colWidths=[16*cm])
            hdr_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,-1), rc.HexColor(dark)),
                ('BOX',        (0,0),(-1,-1), 2, rc.HexColor(accent)),
                ('PADDING',    (0,0),(-1,-1), 10),
            ]))
            story.append(hdr_tbl)
            story.append(Paragraph(desc,
                ps('DC', fontSize=9, textColor=rc.HexColor('#555'),
                   spaceBefore=4, spaceAfter=6)))
            story.append(HRFlowable(width="100%", thickness=1.5,
                                     color=rc.HexColor(accent)))
            story.append(Spacer(1, 0.15*cm))
            story.append(Paragraph(f"Cible analysée : <b>{target}</b>", normal))
            story.append(Spacer(1, 0.2*cm))

            if not raw:
                story.append(Paragraph(
                    f"⚠ Étape « {name} » non exécutée pour cette cible.",
                    ps('NE', fontSize=9, textColor=rc.HexColor('#888'),
                       fontName='Helvetica-Oblique')))
                continue

            # ── ÉTAPE 1 — DÉCOUVRIR ──────────────────────────────────────────
            if step_idx == 0:
                ports    = parsed.get('ports', [])
                services = parsed.get('services', [])
                os_info  = parsed.get('os', 'Non détecté')
                story.append(Paragraph("Résultats de la découverte réseau", h2))
                story.append(Paragraph(
                    f"Nmap a découvert <b>{len(ports)} port(s) ouvert(s)</b> "
                    f"sur <b>{target}</b>. OS détecté : <b>{os_info}</b>.", normal))
                story.append(Spacer(1, 0.25*cm))
                if services:
                    story.append(Paragraph("Tableau des ports et services :", h2))
                    td = [["Port/Proto", "Service", "Bannière / Version"]]
                    for p, s, b in services:
                        td.append([p, s, b])
                    st = Table(td, colWidths=[3*cm, 3.5*cm, 9.5*cm])
                    st.setStyle(TableStyle([
                        ('BACKGROUND', (0,0),(-1,0), rc.HexColor('#1A5276')),
                        ('TEXTCOLOR',  (0,0),(-1,0), rc.white),
                        ('FONTNAME',   (0,0),(-1,0), 'Helvetica-Bold'),
                        ('FONTSIZE',   (0,0),(-1,-1), 8),
                        ('ROWBACKGROUNDS', (0,1),(-1,-1),
                         [rc.HexColor('#EBF5FB'), rc.white]),
                        ('GRID',   (0,0),(-1,-1), 0.4, rc.HexColor('#BDC3C7')),
                        ('PADDING',(0,0),(-1,-1), 4),
                    ]))
                    story.append(st)
                else:
                    story.append(Paragraph("Aucun service identifié.", normal))

            # ── ÉTAPE 2 — CLASSIFIER ─────────────────────────────────────────
            elif step_idx == 1:
                classified = parsed.get('classified', [])
                story.append(Paragraph("Classification des actifs par criticité", h2))
                high = [c for c in classified if c[3]=="HAUTE"]
                med  = [c for c in classified if c[3]=="MOYENNE"]
                low  = [c for c in classified if c[3]=="FAIBLE"]
                story.append(Paragraph(
                    f"<b>{len(classified)}</b> service(s) sur <b>{target}</b> — "
                    f"<font color='red'><b>{len(high)} haute(s)</b></font>, "
                    f"<font color='orange'><b>{len(med)} moyenne(s)</b></font>, "
                    f"<font color='green'><b>{len(low)} faible(s)</b></font>.", normal))
                story.append(Spacer(1, 0.25*cm))
                if classified:
                    td = [["Port/Proto", "Service", "Bannière", "Criticité"]]
                    for port, svc, banner, level, color in classified:
                        td.append([port, svc, banner, level])
                    rs = [
                        ('BACKGROUND', (0,0),(-1,0), rc.HexColor('#6C3483')),
                        ('TEXTCOLOR',  (0,0),(-1,0), rc.white),
                        ('FONTNAME',   (0,0),(-1,0), 'Helvetica-Bold'),
                        ('FONTSIZE',   (0,0),(-1,-1), 8),
                        ('GRID',   (0,0),(-1,-1), 0.4, rc.HexColor('#BDC3C7')),
                        ('PADDING',(0,0),(-1,-1), 4),
                    ]
                    for i, (_, _, _, level, color) in enumerate(classified, 1):
                        rs.append(('TEXTCOLOR', (3,i),(3,i), rc.HexColor(color)))
                        rs.append(('FONTNAME',  (3,i),(3,i), 'Helvetica-Bold'))
                        bg = (rc.HexColor('#FFF5F5') if level=="HAUTE" else
                              rc.HexColor('#FFFDE7') if level=="MOYENNE" else
                              rc.HexColor('#F0FFF4'))
                        rs.append(('BACKGROUND', (0,i),(-1,i), bg))
                    cl = Table(td, colWidths=[3*cm, 3*cm, 7*cm, 3*cm])
                    cl.setStyle(TableStyle(rs))
                    story.append(cl)

            # ── ÉTAPE 3 — ÉVALUER ────────────────────────────────────────────
            elif step_idx == 2:
                vulns = parsed.get('vulns', [])
                story.append(Paragraph("Évaluation des vulnérabilités", h2))
                story.append(Paragraph(
                    f"<b>{len(vulns)}</b> vulnérabilité(s)/problème(s) détecté(s) "
                    f"sur <b>{target}</b>.", normal))
                story.append(Spacer(1, 0.2*cm))
                if vulns:
                    n_c = sum(1 for v in vulns if v[0]=='CRITIQUE')
                    n_h = sum(1 for v in vulns if v[0]=='HAUTE')
                    n_m = sum(1 for v in vulns if v[0]=='MOYENNE')
                    n_i = sum(1 for v in vulns if v[0]=='INFO')
                    res = Table(
                        [["CRITIQUE","HAUTE","MOYENNE","INFO"],
                         [str(n_c), str(n_h), str(n_m), str(n_i)]],
                        colWidths=[4*cm]*4)
                    res.setStyle(TableStyle([
                        ('BACKGROUND',(0,0),(0,0),rc.HexColor('#C0392B')),
                        ('BACKGROUND',(1,0),(1,0),rc.HexColor('#E67E22')),
                        ('BACKGROUND',(2,0),(2,0),rc.HexColor('#F1C40F')),
                        ('BACKGROUND',(3,0),(3,0),rc.HexColor('#2980B9')),
                        ('TEXTCOLOR', (0,0),(-1,0),rc.white),
                        ('FONTNAME',  (0,0),(-1,0),'Helvetica-Bold'),
                        ('FONTSIZE',  (0,0),(-1,-1),11),
                        ('FONTNAME',  (0,1),(-1,1),'Helvetica-Bold'),
                        ('ALIGN',     (0,0),(-1,-1),'CENTER'),
                        ('PADDING',   (0,0),(-1,-1),7),
                        ('INNERGRID', (0,0),(-1,-1),0.5,rc.HexColor('#BDC3C7')),
                        ('BOX',       (0,0),(-1,-1),1,rc.HexColor('#BDC3C7')),
                    ]))
                    story.append(res)
                    story.append(Spacer(1, 0.25*cm))
                    td = [["Sévérité","Référence","Description"]]
                    for score, color, ref, desc_t in vulns[:20]:
                        td.append([score, ref, desc_t])
                    rs = [
                        ('BACKGROUND',(0,0),(-1,0),rc.HexColor('#D35400')),
                        ('TEXTCOLOR', (0,0),(-1,0),rc.white),
                        ('FONTNAME',  (0,0),(-1,0),'Helvetica-Bold'),
                        ('FONTSIZE',  (0,0),(-1,-1),7.5),
                        ('GRID',  (0,0),(-1,-1),0.4,rc.HexColor('#BDC3C7')),
                        ('PADDING',(0,0),(-1,-1),4),
                    ]
                    for i,(score,color,_,_) in enumerate(vulns[:20],1):
                        rs.append(('TEXTCOLOR',(0,i),(0,i),rc.HexColor(color)))
                        rs.append(('FONTNAME', (0,i),(0,i),'Helvetica-Bold'))
                        bg = (rc.HexColor('#FFF5F5') if score=='CRITIQUE' else
                              rc.HexColor('#FFF8EC') if score=='HAUTE'    else
                              rc.HexColor('#FFFFF0') if score=='MOYENNE'  else
                              rc.HexColor('#EEF6FF'))
                        rs.append(('BACKGROUND',(1,i),(-1,i),bg))
                    vt = Table(td, colWidths=[2.5*cm, 3*cm, 10.5*cm])
                    vt.setStyle(TableStyle(rs))
                    story.append(vt)
                else:
                    story.append(Paragraph("✔ Aucune vulnérabilité référencée détectée.", ok_s))

            # ── ÉTAPE 4 — RAPPORTER ──────────────────────────────────────────
            elif step_idx == 3:
                all_vulns  = step_results.get(2,{}).get('data',{}).get('vulns',[])
                all_class  = step_results.get(1,{}).get('data',{}).get('classified',[])
                all_ports  = step_results.get(0,{}).get('data',{}).get('ports',[])
                crits      = [v for v in all_vulns if v[0]=='CRITIQUE']
                hautes     = [v for v in all_vulns if v[0]=='HAUTE']

                story.append(Paragraph("Rapport de synthèse par cible", h2))
                story.append(Paragraph(
                    f"Synthèse complète sur <b>{target}</b> :<br/>"
                    f"• <b>{len(all_ports)}</b> port(s) ouvert(s)<br/>"
                    f"• <b>{len(all_class)}</b> service(s) classifié(s)<br/>"
                    f"• <b>{len(all_vulns)}</b> vulnérabilité(s) évaluée(s)<br/>"
                    f"• <b>{len(crits)}</b> CRITIQUE(S) — action immédiate<br/>"
                    f"• <b>{len(hautes)}</b> HAUTE(S) — correction urgente", normal))
                story.append(Spacer(1, 0.25*cm))

                if crits:
                    risk_text  = "🔴 CRITIQUE — Action immédiate requise"
                    risk_color = "#C0392B"
                elif hautes:
                    risk_text  = "🟠 ÉLEVÉ — Correction urgente recommandée"
                    risk_color = "#E67E22"
                elif all_vulns:
                    risk_text  = "🟡 MODÉRÉ — Correctifs à planifier"
                    risk_color = "#D4AC0D"
                else:
                    risk_text  = "🟢 FAIBLE — Aucune vulnérabilité critique"
                    risk_color = "#27AE60"

                risk_tbl = Table([[Paragraph(
                    f"<b>Niveau de risque global : {risk_text}</b>",
                    ps('RK', fontSize=11, fontName='Helvetica-Bold',
                       textColor=rc.HexColor(risk_color), alignment=TA_CENTER)
                )]], colWidths=[16*cm])
                risk_tbl.setStyle(TableStyle([
                    ('BOX',     (0,0),(-1,-1), 2, rc.HexColor(risk_color)),
                    ('PADDING', (0,0),(-1,-1), 10),
                ]))
                story.append(risk_tbl)
                if crits:
                    story.append(Spacer(1, 0.25*cm))
                    story.append(Paragraph("Vulnérabilités critiques prioritaires :", h2))
                    for _, color, ref, desc_t in crits[:5]:
                        story.append(Paragraph(
                            f"⚠ <b>[{ref}]</b> {desc_t[:100]}",
                            ps('CV', fontSize=9, textColor=rc.HexColor('#C0392B'),
                               leftIndent=10)))

            # ── ÉTAPE 5 — CORRIGER ───────────────────────────────────────────
            elif step_idx == 4:
                actions = parsed.get('actions', [])
                story.append(Paragraph("Plan de remédiation et correctifs", h2))
                story.append(Paragraph(
                    f"<b>{len(actions)}</b> action(s) corrective(s) pour <b>{target}</b>.",
                    normal))
                story.append(Spacer(1, 0.2*cm))
                if actions:
                    for i,(score,color,ref,action) in enumerate(actions,1):
                        row_t = Table([[
                            Paragraph(f"<b>{score}</b>",
                                       ps('SP',fontSize=8,textColor=rc.white,
                                          fontName='Helvetica-Bold',alignment=TA_CENTER)),
                            Paragraph(f"<b>{ref}</b>",
                                       ps('SR',fontSize=8,textColor=rc.HexColor('#2C3E50'))),
                            Paragraph(f"{i}. {action}", normal),
                        ]], colWidths=[2.2*cm, 2.8*cm, 11*cm])
                        row_t.setStyle(TableStyle([
                            ('BACKGROUND',(0,0),(0,0),rc.HexColor(color)),
                            ('PADDING',   (0,0),(-1,-1),5),
                            ('BOX',       (0,0),(-1,-1),0.5,rc.HexColor(color)),
                            ('VALIGN',    (0,0),(-1,-1),'TOP'),
                            ('GRID',      (0,0),(-1,-1),0.3,rc.HexColor('#D5D8DC')),
                        ]))
                        story.append(row_t)
                        story.append(Spacer(1, 0.1*cm))
                else:
                    story.append(Paragraph("✔ Aucune action corrective requise.", ok_s))

            # ── ÉTAPE 6 — VÉRIFIER ───────────────────────────────────────────
            elif step_idx == 5:
                ports_before = step_results.get(0,{}).get('data',{}).get('ports',[])
                vulns_before = step_results.get(2,{}).get('data',{}).get('vulns',[])
                ports_after  = parsed.get('ports', [])
                vulns_after  = parse_evaluate(raw)

                story.append(Paragraph("Vérification post-correction", h2))
                story.append(Paragraph(
                    f"Réscan de vérification sur <b>{target}</b> — comparaison avant/après.",
                    normal))
                story.append(Spacer(1, 0.2*cm))

                comp = [
                    ["Indicateur","Avant correction","Après correction","Évolution"],
                    ["Ports ouverts", str(len(ports_before)), str(len(ports_after)),
                     "✔ Réduit" if len(ports_after)<len(ports_before) else
                     "= Identique" if len(ports_after)==len(ports_before) else "✗ Augmenté"],
                    ["Vulnérabilités", str(len(vulns_before)), str(len(vulns_after)),
                     "✔ Réduit" if len(vulns_after)<len(vulns_before) else
                     "= Identique" if len(vulns_after)==len(vulns_before) else "✗ Augmenté"],
                ]
                comp_tbl = Table(comp, colWidths=[4.5*cm,3.5*cm,3.5*cm,4.5*cm])
                comp_tbl.setStyle(TableStyle([
                    ('BACKGROUND',(0,0),(-1,0),rc.HexColor('#1ABC9C')),
                    ('TEXTCOLOR', (0,0),(-1,0),rc.white),
                    ('FONTNAME',  (0,0),(-1,0),'Helvetica-Bold'),
                    ('FONTSIZE',  (0,0),(-1,-1),9),
                    ('ROWBACKGROUNDS',(0,1),(-1,-1),
                     [rc.HexColor('#E8F8F5'),rc.white]),
                    ('GRID',  (0,0),(-1,-1),0.4,rc.HexColor('#BDC3C7')),
                    ('PADDING',(0,0),(-1,-1),6),
                    ('ALIGN', (0,0),(-1,-1),'CENTER'),
                ]))
                story.append(comp_tbl)
                story.append(Spacer(1, 0.3*cm))

                if len(vulns_after)<len(vulns_before) or len(ports_after)<len(ports_before):
                    concl = "✔ Corrections efficaces — le niveau de risque a diminué."
                    cc    = "#27AE60"
                elif not vulns_before and not ports_before:
                    concl = "ℹ Aucune référence disponible — exécuter d'abord les étapes 1 et 3."
                    cc    = "#2980B9"
                else:
                    concl = "⚠ Certaines vulnérabilités persistent — reprendre le cycle."
                    cc    = "#E67E22"
                story.append(Paragraph(f"<b>{concl}</b>",
                    ps('CL',fontSize=10,textColor=rc.HexColor(cc),
                       fontName='Helvetica-Bold')))

            # ── Sortie brute ─────────────────────────────────────────────────
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph("Sortie brute de l'outil :", h2))
            lines = [l.rstrip() for l in raw.split('\n') if l.strip()][:50]
            for line in lines:
                lo = line.lower()
                if any(w in lo for w in ['error','failed','critical']):
                    tc = rc.HexColor('#E74C3C')
                elif any(w in lo for w in ['warning','warn']):
                    tc = rc.HexColor('#E67E22')
                elif any(w in lo for w in ['open','found','vuln','ok']):
                    tc = rc.HexColor('#27AE60')
                else:
                    tc = rc.HexColor('#2C3E50')
                story.append(Paragraph(
                    line.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;'),
                    ParagraphStyle('RL', parent=small, textColor=tc,
                                   fontName='Courier', spaceAfter=1)))
            if len(lines) == 50:
                story.append(Paragraph("... (tronqué — voir terminal)",
                    ps('tr', fontSize=7.5, fontName='Helvetica-Oblique',
                       textColor=rc.HexColor('#888888'))))

        # Pied de page
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=1,
                                 color=rc.HexColor('#BDC3C7')))
        story.append(Paragraph(
            f"Rapport généré le {now_str} — CyberSec Tool FAFA12 — Cible : {target}",
            footer_s))

        doc.build(story)
        return True, output_path

    except Exception as e:
        import traceback
        return False, traceback.format_exc()

# ══════════════════════════════════════════════
#  THREAD D'EXÉCUTION
# ══════════════════════════════════════════════
class CommandThread(QThread):
    output_signal   = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    progress_signal = pyqtSignal(int)

    def __init__(self, command):
        super().__init__()
        self.command    = command
        self._running   = True
        self.raw_output = ""

    def run(self):
        ts = datetime.now().strftime("%H:%M:%S")
        self.output_signal.emit(
            f"<span style='color:{C['success_light']};'><br>"
            f"[{ts}] ▶ {self.command}</span><br>")
        self.progress_signal.emit(10)
        try:
            process = subprocess.Popen(
                self.command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
            prog = 10
            for line in iter(process.stdout.readline, ""):
                if not self._running:
                    process.terminate(); break
                s = line.rstrip()
                if s:
                    self.raw_output += s + "\n"
                    self.output_signal.emit(self._col(s) + "<br>")
                    if prog < 90:
                        prog = min(90, prog + 1)
                        self.progress_signal.emit(prog)
            process.wait()
            self.progress_signal.emit(100)
            self.finished_signal.emit(process.returncode == 0, self.raw_output)
        except FileNotFoundError:
            tool = self.command.split()[0]
            msg  = f"[ERREUR] '{tool}' non trouvé.\n→ sudo apt install {tool}"
            self.raw_output += msg
            self.output_signal.emit(
                f"<span style='color:{C['danger']};'>{msg.replace(chr(10),'<br>')}</span><br>")
            self.finished_signal.emit(False, self.raw_output)
        except Exception as e:
            msg = f"[ERREUR] {e}"
            self.raw_output += msg
            self.output_signal.emit(
                f"<span style='color:{C['danger']};'>{msg}</span><br>")
            self.finished_signal.emit(False, self.raw_output)

    def _col(self, line):
        lo = line.lower()
        c  = (C["danger"]        if any(w in lo for w in ["error","erreur","failed","critical"]) else
              C["warning"]       if any(w in lo for w in ["warning","warn"]) else
              C["success"]       if any(w in lo for w in ["vuln","found","detected","open","ok"]) else
              C["success_light"] if any(w in lo for w in ["info","note"]) else
              C["text_primary"])
        esc = line.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
        return f"<span style='color:{c};'>{esc}</span>"

    def stop(self):
        self._running = False

# ══════════════════════════════════════════════
#  HELPERS UI
# ══════════════════════════════════════════════
def mk_btn(text, icon="", primary=True, color=None, tip=""):
    b = QPushButton(f"  {icon}  {text}" if icon else text)
    acc = color or C["success"]
    dk = "#059669"; lt = "#34D399"; gl = "#064E3B"
    if primary:
        b.setStyleSheet(
            f"QPushButton{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 {dk},stop:1 {acc});color:#fff;border:none;"
            f"border-radius:9px;padding:10px 18px;font-size:13px;font-weight:600;}}"
            f"QPushButton:hover{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 {acc},stop:1 {lt});}}"
            f"QPushButton:pressed{{background:{dk};}}"
            f"QPushButton:disabled{{background:{C['white_40']};color:{C['white_60']};}}"
        )
    else:
        b.setStyleSheet(
            f"QPushButton{{background:transparent;color:{lt};"
            f"border:1px solid {acc};border-radius:9px;"
            f"padding:8px 14px;font-size:12px;font-weight:500;}}"
            f"QPushButton:hover{{background:{gl};border-color:{lt};}}"
            f"QPushButton:pressed{{background:{dk};}}"
            f"QPushButton:disabled{{border-color:{C['white_40']};color:{C['white_40']};}}"
        )
    if tip: b.setToolTip(tip)
    b.setCursor(Qt.PointingHandCursor)
    b.setMinimumHeight(38)
    return b

def mk_combo(items, accent, parent=None):
    c = QComboBox(parent)
    c.addItems(items)
    c.setStyleSheet(
        f"QComboBox{{background:{C['bg_input']};color:{C['text_primary']};"
        f"border:1px solid {C['border']};border-radius:8px;padding:7px 12px;font-size:12px;}}"
        f"QComboBox:hover{{border-color:{accent};}}"
        f"QComboBox QAbstractItemView{{background:{C['bg_card']};color:{C['text_primary']};"
        f"border:1px solid {accent};selection-background-color:{accent};}}"
    )
    return c

def mk_terminal(title="Terminal"):
    t = QTextEdit()
    t.setReadOnly(True)
    t.setStyleSheet(
        f"QTextEdit{{background:#060A12;color:{C['text_primary']};"
        f"border:1px solid {C['border']};border-radius:10px;"
        f"padding:14px;font-family:'Courier New',monospace;font-size:12px;}}"
    )
    t.setMinimumHeight(180)
    c1=C["success_light"]; c2=C["white"]; c3=C["text_secondary"]
    t.setHtml(
        f"<span style='color:{c1};font-family:monospace;'>"
        f"┌─────────────────────────────────┐<br>"
        f"│ <b style='color:{c2};'>{title}</b><br>"
        f"│ <span style='color:{c3};'>Prêt.</span><br>"
        f"└─────────────────────────────────┘</span>")
    return t

def ahtml(term, html):
    cur = term.textCursor(); cur.movePosition(cur.End)
    term.setTextCursor(cur); term.insertHtml(html)
    cur.movePosition(cur.End); term.setTextCursor(cur)
    term.ensureCursorVisible()

def mk_sep(color=None):
    f = QFrame(); f.setFrameShape(QFrame.HLine)
    f.setStyleSheet(f"background:{color or C['border']};border:none;max-height:1px;")
    return f

def mk_label(text, color=None, size=13, bold=False):
    l = QLabel(text)
    s = f"color:{color or C['text_primary']};font-size:{size}px;"
    if bold: s += "font-weight:700;"
    l.setStyleSheet(s)
    return l

def mk_table(cols, min_h=150, stretch_col=None):
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    if stretch_col is not None:
        t.horizontalHeader().setSectionResizeMode(stretch_col, QHeaderView.Stretch)
    t.setStyleSheet(
        f"QTableWidget{{background:{C['bg_input']};color:{C['text_primary']};"
        f"border:1px solid {C['border']};border-radius:8px;"
        f"gridline-color:{C['border']};}}"
        f"QHeaderView::section{{background:{C['bg_sidebar']};color:{C['white_80']};"
        f"padding:5px;border:1px solid {C['border']};font-weight:600;font-size:12px;}}"
        f"QTableWidget::item{{padding:4px;}}"
    )
    t.setMinimumHeight(min_h)
    t.setEditTriggers(QTableWidget.NoEditTriggers)
    return t

def tbl_item(text, color=None, bold=False):
    it = QTableWidgetItem(text)
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    if color: it.setForeground(QBrush(QColor(color)))
    if bold:  it.setFont(QFont("Segoe UI", 9, QFont.Bold))
    return it

# ══════════════════════════════════════════════
#  ONGLET DE BASE
# ══════════════════════════════════════════════
class BaseStepTab(QWidget):
    run_done = pyqtSignal(int, str)

    def __init__(self, step_idx, target_ref):
        super().__init__()
        self.step_idx   = step_idx
        self.target_ref = target_ref
        self.accent, self.dark = STEP_COLORS[5]
        self.thread     = None
        self.raw_output = ""
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 14, 20, 14)
        lay.setSpacing(10)

        # En-tête coloré
        hdr = QFrame()
        hdr.setStyleSheet(
            f"QFrame{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 {self.dark},stop:1 {self.accent});"
            f"border-radius:10px;border:none;}}")
        hl = QHBoxLayout(hdr); 
        hl.setContentsMargins(16,10,16,10)

        icon_l = QLabel(STEP_ICONS[self.step_idx])
        icon_l.setStyleSheet("font-size:24px;background:transparent;")
        name_l = QLabel(f"Étape {self.step_idx+1} — {STEP_NAMES[self.step_idx]}")
        name_l.setStyleSheet("font-size:16px;font-weight:700;color:#fff;background:transparent;")
        desc_l = QLabel(STEP_DESCS[self.step_idx])
        desc_l.setStyleSheet("font-size:11px;color:rgba(255,255,255,0.75);background:transparent;")
        desc_l.setWordWrap(True)

        self.badge = QLabel("EN ATTENTE")
        """self.badge.setStyleSheet(
            f"color:#fff;font-size:10px;font-weight:700;"
            f"background:{self.dark};border:1px solid {self.accent};"
            f"border-radius:6px;padding:3px 8px;letter-spacing:1px;")"""

        tb = QVBoxLayout(); 
        tb.setSpacing(2)
        #tb.addWidget(name_l)
        tb.addWidget(desc_l)
        #hl.addWidget(icon_l); 
        hl.addSpacing(8)
        hl.addLayout(tb, stretch=1)
        hl.addWidget(self.badge, alignment=Qt.AlignTop)
        lay.addWidget(hdr)

        # Config zone
        self.cfg = QFrame()
        self.cfg.setStyleSheet(
            f"QFrame{{background:{C['bg_card']};"
            f"border:1px solid {C['border']};border-radius:10px;}}")
        self.cfg_lay = QVBoxLayout(self.cfg)
        self.cfg_lay.setContentsMargins(14,12,14,12)
        self.cfg_lay.setSpacing(8)
        self._build_config()
        lay.addWidget(self.cfg)

        # Progressbar
        self.pbar = QProgressBar()
        self.pbar.setValue(0); self.pbar.setTextVisible(False)
        self.pbar.setFixedHeight(5)
        self.pbar.setStyleSheet(
            f"QProgressBar{{background:{C['bg_input']};border:none;border-radius:3px;}}"
            f"QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 {self.dark},stop:1 {self.accent});border-radius:3px;}}")
        lay.addWidget(self.pbar)

        # Terminal
        self.terminal = mk_terminal(f"Terminal — {STEP_NAMES[self.step_idx]}")
        lay.addWidget(self.terminal, stretch=1)

        # Boutons
        br = QHBoxLayout(); br.setSpacing(8)
        self.run_btn  = mk_btn("Lancer",  "▶", primary=True,  color=self.accent)
        self.stop_btn = mk_btn("Arrêter", "■", primary=False, color=self.accent)
        self.clr_btn  = mk_btn("Effacer", "✕", primary=False, color=self.accent)
        self.stop_btn.setEnabled(False)
        self.run_btn.clicked.connect(self._run)
        self.stop_btn.clicked.connect(self._stop)
        self.clr_btn.clicked.connect(lambda: self.terminal.clear())
        br.addWidget(self.run_btn); br.addWidget(self.stop_btn)
        br.addWidget(self.clr_btn)
        self._extra_buttons(br)
        br.addStretch()
        self.info_lbl = QLabel("")
        self.info_lbl.setStyleSheet(f"color:{C['white_60']};font-size:11px;")
        br.addWidget(self.info_lbl)
        lay.addLayout(br)

    def _build_config(self): pass
    def _extra_buttons(self, row): pass
    def _get_command(self): return "echo 'non défini'"

    def _cfg_lbl(self, text):
        l = QLabel(text)
        l.setStyleSheet(f"color:{C['white_80']};font-weight:600;min-width:140px;font-size:12px;")
        return l

    def _note(self, text):
        l = QLabel(text)
        l.setStyleSheet(f"color:{C['text_secondary']};font-size:11px;font-style:italic;")
        l.setWordWrap(True)
        return l

    def _run(self):
        target = self.target_ref.text().strip()
        if not target:
            QMessageBox.warning(self,"Cible","Entrez une cible dans la barre du haut.")
            return
        if not is_valid_target(target):
            QMessageBox.warning(self,"Cible invalide",
                f"« {target} » n'est pas une IP ou URL valide.")
            return
        cmd = self._get_command()
        self.raw_output = ""
        self.run_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self.pbar.setValue(0)
        self.badge.setText("EN COURS")
        self.badge.setStyleSheet(
            f"color:#fff;font-size:10px;font-weight:700;"
            f"background:{self.accent};border:1px solid {self.accent};"
            f"border-radius:6px;padding:3px 8px;letter-spacing:1px;")
        self.info_lbl.setText("En cours...")
        self.cfg.setStyleSheet(
            f"QFrame{{background:{C['bg_card']};"
            f"border:1.5px solid {self.accent};border-radius:10px;}}")
        self.thread = CommandThread(cmd)
        self.thread.output_signal.connect(lambda h: ahtml(self.terminal, h))
        self.thread.finished_signal.connect(self._on_done)
        self.thread.progress_signal.connect(self.pbar.setValue)
        self.thread.start()

    def _stop(self):
        if self.thread and self.thread.isRunning():
            self.thread.stop(); self.thread.wait()
            self._on_done(False, self.thread.raw_output)
            self.info_lbl.setText("Arrêté")

    def _on_done(self, success, raw):
        self.raw_output = raw
        self.run_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.cfg.setStyleSheet(
            f"QFrame{{background:{C['bg_card']};"
            f"border:1px solid {C['border']};border-radius:10px;}}")
        ts = datetime.now().strftime("%H:%M:%S")
        if success:
            self.badge.setText("✔ TERMINÉ")
            self.badge.setStyleSheet(
                "color:#fff;font-size:10px;font-weight:700;"
                "background:#059669;border:1px solid #10B981;"
                "border-radius:6px;padding:3px 8px;letter-spacing:1px;")
            self.info_lbl.setText(f"✔ {ts}")
            ahtml(self.terminal,
                f"<br><span style='color:{C['success']};font-weight:bold;'>"
                f"✔ Terminé — {ts}</span><br>")
        else:
            self.badge.setText("⚠ ERREURS")
            self.badge.setStyleSheet(
                "color:#fff;font-size:10px;font-weight:700;"
                "background:#7F1D1D;border:1px solid #EF4444;"
                "border-radius:6px;padding:3px 8px;letter-spacing:1px;")
            self.info_lbl.setText(f"⚠ {ts}")
        self.run_done.emit(self.step_idx, raw)

# ══════════════════════════════════════════════
#  ONGLET 1 — DÉCOUVRIR
# ══════════════════════════════════════════════
class TabDiscover(BaseStepTab):
    def __init__(self, target_ref):
        super().__init__(0, target_ref)

    def _build_config(self):
        row = QHBoxLayout(); row.setSpacing(8)

        self.mode = mk_combo([
            "Scan rapide        (-F)          ports courants        [nmap]",
            "Scan standard      (-sV)         détection services    [nmap]",
            "Scan complet       (-sV -O -A)   OS + services         [nmap]",
            "Scan SYN           (-sS -sV)     discret               [nmap]",
            "Ping scan          (-sn)         hôtes actifs          [nmap]",
            "─────────────────────────────────────────────────────────────",
            "Scanner Web Flask  (HTTP/HTTPS)  app web + framework   [python]",
            "Scanner Web + port (-p PORT)     port spécifique HTTP  [nmap+python]",
        ], self.accent)
        row.addWidget(self.mode)
        self.cfg_lay.addLayout(row)

        # Étiquette d'info dynamique selon le mode sélectionné
        self.mode_info = self._note(
            "Sélectionnez un mode. "
            "Les modes [python] fonctionnent avec les URLs http://... "
            "Les modes [nmap] nécessitent sudo.")
        self.cfg_lay.addWidget(self.mode_info)
        self.mode.currentIndexChanged.connect(self._on_mode_change)
        self._on_mode_change(0)

    def _on_mode_change(self, idx):
        """Met à jour l'info selon le mode choisi."""
        msgs = [
            "nmap -F 127.0.0.1  — scan rapide des 100 ports courants. ⚠ Utilise l'IP seule (http:// retiré automatiquement).",
            "nmap -sV 127.0.0.1  — détecte les versions de services. Recommandé pour la démo.",
            "nmap -sV -O -A 127.0.0.1  — scan complet avec OS. Lent (~2 min). Nécessite sudo.",
            "nmap -sS -sV 127.0.0.1  — scan SYN furtif. Nécessite sudo.",
            "nmap -sn 127.0.0.1  — vérifie si l'hôte répond (ping). Sans détection de ports.",
            "─── Séparateur ───",
            "python3 scanner_discover.py http://127.0.0.1:5000  — ✅ Fonctionne avec les URLs complètes ! Détecte Flask, Django, Nginx… Recommandé pour votre démo.",
            "nmap -p PORT 127.0.0.1 puis scanner_discover — scan nmap sur le port exact + analyse HTTP.",
        ]
        if idx < len(msgs):
            self.mode_info.setText(msgs[idx])

    def _get_command(self):
        t    = self.target_ref.text().strip()
        idx  = self.mode.currentIndex()
        host = extract_host(t)   # Retire http://, :port pour nmap
        port = extract_port(t)   # Port extrait de l'URL (ex: 5000)

        # ─── Modes nmap : utilise l'IP propre, pas l'URL ───────
        if idx == 0:
            return f"sudo nmap -F {host}"
        elif idx == 1:
            return f"sudo nmap -sV {host}"
        elif idx == 2:
            return f"sudo nmap -sV -O -A {host}"
        elif idx == 3:
            return f"sudo nmap -sS -sV {host}"
        elif idx == 4:
            return f"sudo nmap -sn {host}"
        elif idx == 5:
            # Séparateur — ne rien faire
            return f"echo '─── Choisissez un mode de scan ───'"

        # ─── Mode Scanner Web Flask (index 6) ──────────────────
        elif idx == 6:
            # ✅ Scanner intégré : écrit dans /tmp (jamais d'espaces)
            return build_inline_scanner_command(t)

        # ─── Mode nmap port spécifique + scanner (index 7) ─────
        elif idx == 7:
            port_str = str(port) if port else "5000"
            scan_cmd = build_inline_scanner_command(t)
            return (f'sudo nmap -sV -p {port_str} {host} && '
                    f'echo "--- Scanner Web ---" && '
                    f'{scan_cmd}')

        return f"sudo nmap -sV {host}"

# ══════════════════════════════════════════════
#  ONGLET 2 — CLASSIFIER
# ══════════════════════════════════════════════
class TabClassify(BaseStepTab):
    def __init__(self, target_ref):
        super().__init__(1, target_ref)
        self.classified = []

    def _build_config(self):
        self.cfg_lay.addWidget(self._note(
            "Utilise les résultats de l'étape Découvrir pour classer les services "
            "par criticité (HAUTE / MOYENNE / FAIBLE). Lance un scan rapide si "
            "l'étape 1 n'a pas encore été exécutée."))
        self.table = mk_table(["Port/Proto","Service","Bannière","Criticité"],
                               min_h=150, stretch_col=2)
        self.cfg_lay.addWidget(self.table)

    def populate(self, raw_discover):
        _, services, _ = parse_discover(raw_discover)
        self.classified = parse_classify(raw_discover, services)
        self.table.setRowCount(0)
        for port, svc, banner, level, color in self.classified:
            r = self.table.rowCount(); self.table.insertRow(r)
            self.table.setItem(r, 0, tbl_item(port))
            self.table.setItem(r, 1, tbl_item(svc))
            self.table.setItem(r, 2, tbl_item(banner))
            self.table.setItem(r, 3, tbl_item(level, color=color, bold=True))
        ahtml(self.terminal,
            f"<span style='color:{C['success']};'>✔ {len(self.classified)} "
            f"service(s) classifié(s)</span><br>")

    def _get_command(self):
        host = extract_host(self.target_ref.text().strip())
        return f"sudo nmap -sV -F {host}"

    def _on_done(self, success, raw):
        if not self.classified:
            self.populate(raw)
        super()._on_done(success, raw)

# ══════════════════════════════════════════════
#  ONGLET 3 — ÉVALUER
# ══════════════════════════════════════════════
class TabEvaluate(BaseStepTab):
    def __init__(self, target_ref):
        super().__init__(2, target_ref)
        self.vulns = []

    def _build_config(self):
        row = QHBoxLayout(); row.setSpacing(8)
        row.addWidget(self._cfg_lbl("Outil :"))
        self.tool = mk_combo([
            "Scanner SQLi Flask — SQLi + Headers + BruteForce  [python]",
            "Nikto              — Scanner web (XSS, injections) [nikto]",
            "Nmap NSE vuln      — Scripts vulnérabilités réseau [nmap]",
            "Nmap NSE exploit   — Scripts d'exploitation        [nmap]",
            "WhatWeb            — Empreinte & versions          [whatweb]",
        ], self.accent)
        row.addWidget(self.tool)
        self.cfg_lay.addLayout(row)

        self.eval_info = self._note(
            "✅ Scanner SQLi Flask : intégré — aucune installation requise. "
            "Recommandé pour la démo.")
        self.cfg_lay.addWidget(self.eval_info)
        self.tool.currentIndexChanged.connect(self._on_tool_change)
        self._on_tool_change(0)

    def _on_tool_change(self, idx):
        msgs = [
            "✅ Scanner SQLi Flask — intégré dans app.py, aucun outil à installer. "
            "Teste : SQL Injection (4 payloads), en-têtes HTTP manquants, "
            "absence de rate-limiting, erreurs SQL exposées. Recommandé pour la démo.",
            "nikto -h http://127.0.0.1:5000 — nécessite : sudo apt install nikto",
            "sudo nmap --script vuln — nécessite sudo + nmap installé",
            "sudo nmap --script exploit — nécessite sudo + nmap installé",
            "whatweb -v — nécessite : sudo apt install whatweb",
        ]
        if idx < len(msgs):
            self.eval_info.setText(msgs[idx])

    def _get_command(self):
        t    = self.target_ref.text().strip()
        host = extract_host(t)
        idx  = self.tool.currentIndex()
        if idx == 0:
            return build_inline_sqli_command(t)
        return [
            build_inline_sqli_command(t),
            f"nikto -h {t}",
            f"sudo nmap --script vuln -sV {host}",
            f"sudo nmap --script exploit -sV {host}",
            f"whatweb -v {t}",
        ][idx]

    def _on_done(self, success, raw):
        self.vulns = parse_evaluate(raw)
        ahtml(self.terminal,
            f"<span style='color:{C['success']};'>✔ {len(self.vulns)} "
            f"vulnérabilité(s) détectée(s)</span><br>")
        super()._on_done(success, raw)

# ══════════════════════════════════════════════
#  ONGLET 4 — RAPPORTER
# ══════════════════════════════════════════════
class TabReport(BaseStepTab):
    def __init__(self, target_ref, step_results_ref):
        self._sr = step_results_ref
        super().__init__(3, target_ref)
        self._last_pdf = ""

    def _build_config(self):
        self.cfg_lay.addWidget(self._note(
            "Génère le rapport PDF complet structuré en 6 sections — "
            "une section par étape du cycle — avec les résultats réels "
            "obtenus sur la cible. Exécutez les étapes 1–3 d'abord."))

    def _extra_buttons(self, row):
        self.pdf_btn = mk_btn("Ouvrir PDF","📄",primary=False,color=self.accent)
        self.pdf_btn.setEnabled(False)
        self.pdf_btn.clicked.connect(self._open_pdf)
        row.addWidget(self.pdf_btn)

        self.save_btn = mk_btn("Enregistrer log","💾",primary=False,color=self.accent)
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self._save_log)
        row.addWidget(self.save_btn)

    def _get_command(self):
        return f"echo 'Génération du rapport pour {self.target_ref.text().strip()}'"

    def _on_done(self, success, raw):
        target = self.target_ref.text().strip()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        outdir = os.path.expanduser("~/CyberSec_Rapports")
        os.makedirs(outdir, exist_ok=True)
        safe = re.sub(r'[^a-zA-Z0-9_]','_',target)
        path = os.path.join(outdir, f"rapport_cycle_{safe}_{ts}.pdf")

        ahtml(self.terminal,
            f"<span style='color:{C['success_light']};'>⚙ Génération PDF...</span><br>")

        # S'assurer que les données corriger sont incluses
        if 4 not in self._sr and hasattr(self, '_remediate_ref'):
            actions = self._remediate_ref.actions
            self._sr[4] = {'raw': 'Plan généré automatiquement.',
                           'data': {'actions': actions}}

        ok, result = generate_pdf_report(target, self._sr, path)
        if ok:
            self._last_pdf = result
            self.pdf_btn.setEnabled(True)
            self.save_btn.setEnabled(True)
            ahtml(self.terminal,
                f"<span style='color:{C['success']};font-weight:bold;'>"
                f"📄 PDF généré : {result}</span><br>")
        else:
            ahtml(self.terminal,
                f"<span style='color:{C['warning']};'>⚠ Erreur :<br>{result[:300]}</span><br>")
        super()._on_done(success, raw)

    def _open_pdf(self):
        if self._last_pdf and os.path.exists(self._last_pdf):
            for v in ["evince","okular","atril","xdg-open"]:
                try:
                    subprocess.Popen([v,self._last_pdf],
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
                    return
                except FileNotFoundError:
                    continue
            QMessageBox.information(self,"PDF",f"Rapport : {self._last_pdf}")

    def _save_log(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(
            self,"Enregistrer log",
            os.path.expanduser(f"~/CyberSec_Rapports/log_{ts}.txt"),
            "Fichiers texte (*.txt)")
        if path:
            all_raw = "\n\n".join(
                f"=== {STEP_NAMES[i]} ===\n{self._sr.get(i,{}).get('raw','')}"
                for i in range(6))
            try:
                with open(path,'w',encoding='utf-8') as f:
                    f.write(f"CyberSec Tool — Log cycle complet\n"
                            f"Cible : {self.target_ref.text().strip()}\n"
                            f"Date  : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
                            f"{'='*60}\n\n{all_raw}")
                ahtml(self.terminal,
                    f"<span style='color:{C['success']};'>💾 Log : {path}</span><br>")
            except Exception as e:
                ahtml(self.terminal,
                    f"<span style='color:{C['danger']};'>✖ {e}</span><br>")

# ══════════════════════════════════════════════
#  ONGLET 5 — CORRIGER
# ══════════════════════════════════════════════
class TabRemediate(BaseStepTab):
    def __init__(self, target_ref):
        super().__init__(4, target_ref)
        self.actions = []

    def _build_config(self):
        self.cfg_lay.addWidget(self._note(
            "Plan de remédiation basé sur les vulnérabilités de l'étape 3 (Évaluer). "
            "Les actions correctives sont générées automatiquement et classées par priorité."))
        self.table = mk_table(["Priorité","Référence","Action corrective"],
                               min_h=180, stretch_col=2)
        self.cfg_lay.addWidget(self.table)

    def populate(self, vulns, classified):
        self.actions = parse_remediation(vulns, classified)
        self.table.setRowCount(0)
        for score, color, ref, action in self.actions:
            r = self.table.rowCount(); self.table.insertRow(r)
            self.table.setItem(r, 0, tbl_item(score, color=color, bold=True))
            self.table.setItem(r, 1, tbl_item(ref))
            self.table.setItem(r, 2, tbl_item(action))
        ahtml(self.terminal,
            f"<span style='color:{C['success']};'>✔ {len(self.actions)} "
            f"action(s) corrective(s)</span><br>")

    def _get_command(self):
        return f"echo 'Plan de remédiation — {self.target_ref.text().strip()}'"

    def _on_done(self, success, raw):
        if not self.actions:
            ahtml(self.terminal,
                f"<span style='color:{C['warning']};'>"
                f"⚠ Exécutez l'étape 3 (Évaluer) d'abord.</span><br>")
        super()._on_done(success, raw)

# ══════════════════════════════════════════════
#  ONGLET 6 — VÉRIFIER
# ══════════════════════════════════════════════
class TabVerify(BaseStepTab):
    def __init__(self, target_ref):
        super().__init__(5, target_ref)
        self.ports_before = []
        self.vulns_before = []

    def _build_config(self):
        row = QHBoxLayout(); row.setSpacing(8)
        row.addWidget(self._cfg_lbl("Outil :"))
        self.tool = mk_combo([
            "Nmap -sV         — Rescanner les services",
            "Nikto            — Rescanner les vulnérabilités web",
            "Nmap NSE vuln    — Rescanner les scripts vuln",
            "Scanner Web      — Rescanner le service Flask/HTTP",
        ], self.accent)
        row.addWidget(self.tool)
        self.cfg_lay.addLayout(row)
        self.compare_lbl = QLabel("En attente des résultats des étapes 1 et 3...")
        self.compare_lbl.setStyleSheet(
            f"color:{C['text_secondary']};font-size:12px;")
        self.cfg_lay.addWidget(self.compare_lbl)

    def set_baselines(self, ports, vulns):
        self.ports_before = ports
        self.vulns_before = vulns
        self.compare_lbl.setText(
            f"Référence avant correctifs : {len(ports)} port(s) — "
            f"{len(vulns)} vulnérabilité(s).")

    def _get_command(self):
        t    = self.target_ref.text().strip()
        host = extract_host(t)
        scan_cmd = build_inline_scanner_command(t)
        return [f"sudo nmap -sV -F {host}",
                f"nikto -h {t}",
                f"sudo nmap --script vuln -sV {host}",
                scan_cmd,
                ][min(self.tool.currentIndex(), 3)]

    def _on_done(self, success, raw):
        pa = len(parse_discover(raw)[0])
        va = len(parse_evaluate(raw))
        pb = len(self.ports_before); vb = len(self.vulns_before)
        dp = pb - pa; dv = vb - va
        ps_str = f"✔ -{dp}" if dp > 0 else (f"= 0" if dp == 0 else f"✗ +{-dp}")
        vs_str = f"✔ -{dv}" if dv > 0 else (f"= 0" if dv == 0 else f"✗ +{-dv}")
        self.compare_lbl.setText(
            f"Ports : {pb} → {pa} ({ps_str})   |   "
            f"Vulnérabilités : {vb} → {va} ({vs_str})")
        if dv > 0 or dp > 0:
            msg = f"✔ Corrections efficaces : {dv} vuln(s) et {dp} port(s) éliminé(s)."
            c   = C["success"]
        elif dv == 0 and dp == 0 and (pb or vb):
            msg = "⚠ Aucune réduction — vérifiez l'application des correctifs."
            c   = C["warning"]
        else:
            msg = "ℹ Aucune référence — exécutez d'abord les étapes 1 et 3."
            c   = C["info"]
        ahtml(self.terminal,
            f"<br><span style='color:{c};font-weight:bold;'>{msg}</span><br>")
        super()._on_done(success, raw)

# ══════════════════════════════════════════════
#  FENÊTRE PRINCIPALE
# ══════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberSec Tool — Sujet 2 : Gestion des Vulnérabilités")
        self.setMinimumSize(1080, 700)
        self.resize(1340, 850)
        self.setStyleSheet(
            f"QMainWindow,QWidget{{background:{C['bg_main']};"
            f"color:{C['text_primary']};"
            f"font-family:'Segoe UI','Helvetica Neue',Arial,sans-serif;font-size:13px;}}"
            f"QScrollBar:vertical{{background:{C['bg_card']};width:6px;border-radius:3px;}}"
            f"QScrollBar::handle:vertical{{background:{C['success']};border-radius:3px;min-height:30px;}}"
            f"QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}"
            f"QScrollBar:horizontal{{background:{C['bg_card']};height:6px;border-radius:3px;}}"
            f"QScrollBar::handle:horizontal{{background:{C['success']};border-radius:3px;}}"
            f"QToolTip{{background:{C['bg_card']};color:{C['white']};"
            f"border:1px solid {C['success']};border-radius:6px;padding:5px 9px;}}"
        )
        self.step_results = {}
        self._build_ui()
        self._center()

    def _center(self):
        g = self.geometry(); s = QApplication.primaryScreen().geometry()
        self.move((s.width()-g.width())//2, (s.height()-g.height())//2)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── Barre du haut ─────────────────────────────────────────────────────
        topbar = QFrame()
        topbar.setFixedHeight(62)
        topbar.setStyleSheet(
            f"QFrame{{background:{C['bg_sidebar']};"
            f"border-bottom:1px solid {C['border']};}}")
        tl = QHBoxLayout(topbar)
        tl.setContentsMargins(18,0,18,0); tl.setSpacing(12)

        logo = QLabel("🛡️ Gestion de vulnérabilité")
        logo.setStyleSheet(f"font-size:16px;font-weight:800;color:{C['white']};")
        tl.addWidget(logo)

        vsep = QFrame(); vsep.setFrameShape(QFrame.VLine)
        vsep.setStyleSheet(f"background:{C['border']};border:none;max-width:1px;margin:14px 0;")
        tl.addWidget(vsep)

        tl.addWidget(mk_label("Cible :", C["white_60"], 12, bold=True))

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.10  ou  http://cible.local")
        self.target_input.setText("192.168.1.10")
        self.target_input.setMinimumWidth(280)
        self.target_input.setStyleSheet(
            f"QLineEdit{{background:{C['bg_input']};color:{C['text_primary']};"
            f"border:1px solid {C['border']};border-radius:8px;"
            f"padding:7px 13px;font-size:13px;font-weight:600;}}"
            f"QLineEdit:focus{{border-color:{C['success']};background:#1E2A42;}}")
        tl.addWidget(self.target_input)

        self.valid_lbl = QLabel("● ...")
        self.valid_lbl.setStyleSheet(f"color:{C['white_60']};font-size:11px;font-weight:600;")
        self.target_input.textChanged.connect(self._update_valid)
        tl.addWidget(self.valid_lbl)
        tl.addStretch()

        # Pastilles indicateur cycle
        self.pills = []
        for i, (icon, name) in enumerate(zip(STEP_ICONS, STEP_NAMES)):
            acc, dark = STEP_COLORS[7]
            p = QPushButton(f"{name}")
            p.setStyleSheet(
                f"QPushButton{{background:{dark};color:{acc};"
                f"border:1px solid {acc};border-radius:11px;"
                f"padding:3px 9px;font-size:10px;font-weight:600;}}"
                f"QPushButton:hover{{background:{acc};color:#fff;}}")
            p.setFixedHeight(24); p.setCursor(Qt.PointingHandCursor)
            p.clicked.connect(lambda _, idx=i: self.tabs.setCurrentIndex(idx))
            self.pills.append(p); tl.addWidget(p)
    
        root.addWidget(topbar)

        # ── Corps : sidebar + onglets ─────────────────────────────────────────
        body = QWidget()
        bl = QHBoxLayout(body); bl.setContentsMargins(0,0,0,0); bl.setSpacing(0)
        bl.addWidget(self._build_sidebar())

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{C['bg_main']};}}"
            f"QTabBar::tab{{background:{C['bg_card']};color:{C['white_60']};"
            f"padding:9px 16px;border:none;font-size:12px;font-weight:600;"
            f"border-bottom:3px solid transparent;margin-right:2px;}}"
            f"QTabBar::tab:selected{{color:{C['white']};"
            f"border-bottom:3px solid {C['success']};}}"
            f"QTabBar::tab:hover{{color:{C['white']};background:{C['bg_sidebar']};}}")

        # Instancier les 6 onglets
        self.t_disc = TabDiscover(self.target_input)
        self.t_clas = TabClassify(self.target_input)
        self.t_eval = TabEvaluate(self.target_input)
        self.t_repo = TabReport(self.target_input, self.step_results)
        self.t_reme = TabRemediate(self.target_input)
        self.t_veri = TabVerify(self.target_input)

        # Référence croisée pour que Rapporter puisse accéder aux actions Corriger
        self.t_repo._remediate_ref = self.t_reme

        for widget, name in [
            (self.t_disc, "Découvrir"),
            (self.t_clas, "Classifier"),
            (self.t_eval, "Évaluer"),
            (self.t_repo, "Rapporter"),
            (self.t_reme, "Corriger"),
            (self.t_veri, "Vérifier"),
        ]:
            sc = QScrollArea(); sc.setWidget(widget); sc.setWidgetResizable(True)
            sc.setStyleSheet(f"QScrollArea{{background:{C['bg_main']};border:none;}}")
            self.tabs.addTab(sc, name)

        # Connexions de propagation entre étapes
        self.t_disc.run_done.connect(self._after_discover)
        self.t_clas.run_done.connect(self._after_classify)
        self.t_eval.run_done.connect(self._after_evaluate)
        self.t_repo.run_done.connect(self._after_generic)
        self.t_reme.run_done.connect(self._after_remediate)
        self.t_veri.run_done.connect(self._after_verify)

        bl.addWidget(self.tabs, stretch=1)
        root.addWidget(body, stretch=1)

    def _build_sidebar(self):
        sb = QFrame(); sb.setFixedWidth(195)
        sb.setStyleSheet(
            f"QFrame{{background:{C['bg_sidebar']};"
            f"border-right:1px solid {C['border']};}}")
        lay = QVBoxLayout(sb)
        lay.setContentsMargins(10,14,10,14); lay.setSpacing(4)
        lay.addWidget(mk_label("Cycle complet", C["white_80"], 12, bold=True))
        lay.addWidget(mk_sep()); lay.addSpacing(4)

        self.sb_btns = []
        for i, (icon, name) in enumerate(zip(STEP_ICONS, STEP_NAMES)):
            #acc, dark = STEP_COLORS[i]
            acc, dark = STEP_COLORS[6]
            b = QPushButton(f" {name}")
            b.setStyleSheet(
                f"QPushButton{{background:{dark};color:{acc};"
                f"border:1px solid {acc};border-radius:8px;"
                f"padding:8px 10px;font-size:12px;font-weight:600;"
                f"text-align:center;}}"
                f"QPushButton:hover{{background:#8899CC;color:#00F;}}")
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _, idx=i: self.tabs.setCurrentIndex(idx))
            self.sb_btns.append(b); lay.addWidget(b)

        lay.addStretch()
        lay.addWidget(mk_sep()); lay.addSpacing(4)
        lay.addWidget(mk_label("Avancement", C["white_60"], 10, bold=True))
        self.gpbar = QProgressBar()
        self.gpbar.setValue(0); self.gpbar.setFixedHeight(16)
        self.gpbar.setFormat("%p% terminé"); self.gpbar.setTextVisible(True)
        self.gpbar.setStyleSheet(
            f"QProgressBar{{background:{C['bg_input']};border:none;"
            f"border-radius:8px;color:{C['white']};font-size:10px;font-weight:600;}}"
            f"QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 #059669,stop:1 #34D399);border-radius:8px;}}")
        lay.addWidget(self.gpbar)
        lay.addSpacing(6)
        lay.addWidget(mk_label("v2.0  PyQt5  Python 3",C["white_40"],10))
        return sb

    def _update_valid(self, text):
        ok = is_valid_target(text.strip())
        self.valid_lbl.setText("● Valide" if ok else "● Invalide")
        self.valid_lbl.setStyleSheet(
            f"color:{C['success'] if ok else C['danger']};"
            f"font-size:11px;font-weight:600;")

    def _update_progress(self):
        done = sum(1 for v in self.step_results.values() if v.get('raw','').strip())
        self.gpbar.setValue(int(done/6*100))
        for i, pill in enumerate(self.pills):
            acc, dark = STEP_COLORS[7]
            finished = bool(self.step_results.get(i,{}).get('raw','').strip())
            if finished:
                pill.setStyleSheet(
                    f"QPushButton{{background:{acc};color:#fff;"
                    f"border:1px solid {acc};border-radius:11px;"
                    f"padding:3px 9px;font-size:10px;font-weight:700;}}"
                    f"QPushButton:hover{{background:{acc};color:#fff;}}")
            else:
                pill.setStyleSheet(
                    f"QPushButton{{background:{dark};color:{acc};"
                    f"border:1px solid {acc};border-radius:11px;"
                    f"padding:3px 9px;font-size:10px;font-weight:600;}}"
                    f"QPushButton:hover{{background:{acc};color:#fff;}}")

    # ── Propagation ──────────────────────────────────────────────────────────
    def _after_discover(self, idx, raw):
        ports, services, os_info = parse_discover(raw)
        self.step_results[0] = {
            'raw': raw,
            'data': {'ports': ports, 'services': services, 'os': os_info}
        }
        self.t_clas.populate(raw)
        self._update_progress()

    def _after_classify(self, idx, raw):
        self.step_results[1] = {
            'raw': raw,
            'data': {'classified': self.t_clas.classified}
        }
        self._update_progress()

    def _after_evaluate(self, idx, raw):
        vulns = parse_evaluate(raw)
        self.step_results[2] = {'raw': raw, 'data': {'vulns': vulns}}
        classified = self.step_results.get(1,{}).get('data',{}).get('classified',[])
        self.t_reme.populate(vulns, classified)
        ports = self.step_results.get(0,{}).get('data',{}).get('ports',[])
        self.t_veri.set_baselines(ports, vulns)
        self._update_progress()

    def _after_generic(self, idx, raw):
        self.step_results.setdefault(idx, {})['raw'] = raw
        self._update_progress()

    def _after_remediate(self, idx, raw):
        self.step_results[4] = {
            'raw': raw,
            'data': {'actions': self.t_reme.actions}
        }
        self._update_progress()

    def _after_verify(self, idx, raw):
        ports_after = parse_discover(raw)[0]
        vulns_after = parse_evaluate(raw)
        self.step_results[5] = {
            'raw': raw,
            'data': {'ports': ports_after, 'vulns': vulns_after}
        }
        self._update_progress()

# ══════════════════════════════════════════════
#  POINT D'ENTRÉE
# ══════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("CyberSec Tool - Sujet 2")
    app.setFont(QFont("Segoe UI", 10))
    pal = QPalette()
    pal.setColor(QPalette.Window,          QColor(C["bg_main"]))
    pal.setColor(QPalette.WindowText,      QColor(C["text_primary"]))
    pal.setColor(QPalette.Base,            QColor(C["bg_input"]))
    pal.setColor(QPalette.AlternateBase,   QColor(C["bg_card"]))
    pal.setColor(QPalette.Text,            QColor(C["text_primary"]))
    pal.setColor(QPalette.Button,          QColor(C["bg_card"]))
    pal.setColor(QPalette.ButtonText,      QColor(C["white"]))
    pal.setColor(QPalette.Highlight,       QColor(C["success"]))
    pal.setColor(QPalette.HighlightedText, QColor(C["white"]))
    app.setPalette(pal)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()