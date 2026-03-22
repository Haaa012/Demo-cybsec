#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ÉVALUATION DES RISQUES – Sujet 1
Fonctionnalités : Scanner Nmap + Scénarios auto + Matrice 5x5 + Registre + PDF complet
"""

import sys
import subprocess
import os
import re
from datetime import datetime
from html import escape

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox,
    QProgressBar, QGroupBox, QFormLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QTabWidget, QScrollArea, QDialog, QDialogButtonBox,
    QSpinBox, QFrame, QSplitter
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QBrush

# ==================== CONSTANTES ====================
COLORS = {
    "bg": "#0f1117", "input": "#21262d", "border": "#30363d",
    "text": "#c9d1d9", "accent": "#58a6ff", "success": "#3fb950",
}

RISK_COLORS = {
    "Tres Eleve": "#7f1d1d",
    "Eleve":      "#ef4444",
    "Modere":     "#d97706",
    "Faible":     "#166534",
    "Tres Faible":"#1a4731",
}

PROB_LABELS = {1: "Rare", 2: "Peu probable", 3: "Possible", 4: "Probable", 5: "Tres probable"}
IMP_LABELS  = {1: "Negligeable", 2: "Mineur", 3: "Modere", 4: "Grave", 5: "Tres grave"}


def risk_level(prob, imp):
    s = prob * imp
    if s >= 20: return "Tres Eleve"
    if s >= 12: return "Eleve"
    if s >= 6:  return "Modere"
    if s >= 3:  return "Faible"
    return "Tres Faible"


def risk_label_fr(rl):
    return {
        "Tres Eleve": "Très Élevé", "Eleve": "Élevé",
        "Modere": "Modéré", "Faible": "Faible", "Tres Faible": "Très Faible"
    }.get(rl, rl)


# ==================== SCÉNARIOS PAR SERVICE ====================
SERVICE_SCENARIOS = {
    "domain": {
        "scenario": "Un attaquant effectue une attaque DNS poisoning ou un transfert de zone non autorisé sur le serveur DNS exposé, redirigeant le trafic légitime vers un serveur malveillant.",
        "vulnerability": "Port 53 ouvert sans restriction — transfert de zone non filtré, résolveur DNS récursif public",
        "asset": "Serveur DNS, infrastructure réseau, utilisateurs finaux",
        "consequence": "Redirection du trafic, vol de données, phishing, déni de service par amplification DNS",
        "prob_default": 4, "imp_default": 4,
        "measures": "Filtrage partiel des requêtes DNS",
        "treatment": "Restreindre les transferts de zone (named.conf)\nActiver DNSSEC\nBloquer port 53 depuis l'extérieur si usage interne\nOutil : dig axfr @<ip> pour audit"
    },
    "http-proxy": {
        "scenario": "Un attaquant exploite le proxy HTTP ouvert pour intercepter des communications ou l'utiliser comme relais pour des attaques externes (open proxy).",
        "vulnerability": "Proxy HTTP ouvert sans authentification, port 8080 accessible depuis l'extérieur",
        "asset": "Flux réseau, données en transit, réputation de l'organisation",
        "consequence": "Interception de données en clair, utilisation comme proxy de rebond, vol de credentials",
        "prob_default": 4, "imp_default": 3,
        "measures": "Aucune authentification proxy détectée",
        "treatment": "Ajouter authentification obligatoire sur le proxy\nRestreindre l'accès aux IP internes (ufw)\nSurveiller les logs proxy\nOutil : curl -x http://<ip>:8080 pour tester l'open proxy"
    },
    "blackice": {
        "scenario": "Un attaquant exploite le service BlackIce exposé pour accéder aux alertes de sécurité ou désactiver les mécanismes de détection d'intrusion.",
        "vulnerability": "Service de sécurité BlackIce exposé sur port 8082 sans protection, potentiellement vulnérable à des CVE connues",
        "asset": "Système de détection d'intrusion, journaux de sécurité, infrastructure de monitoring",
        "consequence": "Désactivation de la surveillance sécurité, accès aux logs sensibles, attaques non détectées",
        "prob_default": 3, "imp_default": 5,
        "measures": "Service actif mais non filtré",
        "treatment": "Bloquer le port 8082 depuis l'extérieur (ufw deny 8082)\nMigrer vers IDS/IPS moderne (Snort, Suricata)\nAudit CVE BlackIce sur NVD NIST\nOutil : nmap --script vuln <ip> -p 8082"
    },
    "ssh": {
        "scenario": "Un attaquant effectue une attaque par force brute contre SSH ou exploite une version vulnérable pour obtenir un accès root.",
        "vulnerability": "SSH exposé sur port standard 22, authentification par mot de passe autorisée, pas de fail2ban détecté",
        "asset": "Accès administrateur système, ensemble de l'infrastructure",
        "consequence": "Accès root non autorisé, installation de backdoor, pivoting réseau, ransomware",
        "prob_default": 4, "imp_default": 5,
        "measures": "Authentification par mot de passe uniquement",
        "treatment": "Désactiver l'auth par mot de passe, utiliser les clés SSH\nInstaller fail2ban (apt install fail2ban)\nChanger le port SSH (ex: 2222)\nRestreindre l'accès SSH par IP (ufw allow from <ip> to any port 22)"
    },
    "http": {
        "scenario": "Un attaquant exploite une vulnérabilité sur le service HTTP (injection SQL, XSS, CSRF) pour accéder aux données sensibles.",
        "vulnerability": "Service HTTP non chiffré, version potentiellement obsolète, absence de WAF",
        "asset": "Serveur web, données applicatives, utilisateurs connectés",
        "consequence": "Vol de données, prise de contrôle du serveur, défacement, propagation",
        "prob_default": 4, "imp_default": 4,
        "measures": "Pare-feu applicatif partiel",
        "treatment": "Migrer vers HTTPS (certbot)\nMettre à jour le serveur web\nDéployer un WAF (ModSecurity)\nOutil : nikto -h <ip>"
    },
    "ftp": {
        "scenario": "Un attaquant accède au serveur FTP avec le compte anonyme ou par force brute pour exfiltrer des fichiers sensibles.",
        "vulnerability": "FTP non chiffré, potentiel accès anonyme, credentials transmis en clair",
        "asset": "Fichiers partagés, données sensibles",
        "consequence": "Exfiltration de données, modification de fichiers",
        "prob_default": 5, "imp_default": 4,
        "measures": "Aucune mesure détectée",
        "treatment": "Désactiver FTP, migrer vers SFTP ou FTPS\nBloquer le port 21 (ufw deny 21)\nOutil : nmap --script ftp-anon <ip>"
    },
    "smb": {
        "scenario": "Un attaquant exploite SMB (EternalBlue/MS17-010) ou des identifiants par défaut pour accéder aux partages réseau et propager un ransomware.",
        "vulnerability": "SMB exposé, possibilité d'exploitation EternalBlue si non patché",
        "asset": "Partages réseau, fichiers d'entreprise, domaine Windows",
        "consequence": "Propagation de ransomware, vol de données, compromission du domaine AD",
        "prob_default": 4, "imp_default": 5,
        "measures": "Partages potentiellement exposés",
        "treatment": "Bloquer port 445 depuis l'extérieur (ufw deny 445)\nAppliquer patch MS17-010\nDésactiver SMBv1\nOutil : nmap --script smb-vuln-ms17-010 <ip>"
    },
    "mysql": {
        "scenario": "Un attaquant accède directement à la base MySQL exposée avec des credentials par défaut pour exfiltrer toutes les données.",
        "vulnerability": "MySQL exposé sur port public, compte root potentiellement sans mot de passe",
        "asset": "Base de données complète, données personnelles",
        "consequence": "Vol ou destruction de données, violation RGPD, sabotage applicatif",
        "prob_default": 5, "imp_default": 5,
        "measures": "Aucune restriction réseau détectée",
        "treatment": "Bloquer port 3306 (ufw deny 3306)\nRestreindre MySQL à localhost (bind-address=127.0.0.1)\nChanger mot de passe root\nOutil : mysql -h <ip> -u root (test accès sans MDP)"
    },
    "rdp": {
        "scenario": "Un attaquant effectue une force brute sur RDP ou exploite BlueKeep (CVE-2019-0708) pour prendre le contrôle du serveur Windows.",
        "vulnerability": "RDP exposé sur port 3389, sans NLA, potentiellement vulnérable à BlueKeep",
        "asset": "Poste ou serveur Windows, données et applications",
        "consequence": "Prise de contrôle complète, installation de malware, pivoting",
        "prob_default": 5, "imp_default": 5,
        "measures": "Authentification RDP basique",
        "treatment": "Bloquer port 3389 (ufw deny 3389)\nActiver NLA\nUtiliser VPN pour accès RDP\nAppliquer patch BlueKeep"
    },
}

DEFAULT_SCENARIO = {
    "scenario": "Un attaquant exploite le service exposé sur ce port pour obtenir un accès non autorisé ou perturber le réseau.",
    "vulnerability": "Port ouvert sans restriction d'accès identifiée, service potentiellement non patché",
    "asset": "Service réseau, hôte exposé",
    "consequence": "Accès non autorisé, perturbation de service, exfiltration de données",
    "prob_default": 3, "imp_default": 3,
    "measures": "A définir",
    "treatment": "Analyser la nécessité d'exposition de ce port\nAppliquer le principe du moindre privilège\nOutil : nmap -sV --script vuln <ip>"
}


def get_scenario(service_name):
    svc = service_name.lower()
    for key in SERVICE_SCENARIOS:
        if key in svc:
            return SERVICE_SCENARIOS[key].copy()
    return DEFAULT_SCENARIO.copy()


def auto_scenarios(ports_raw):
    result = []
    for i, (port_str, svc_name) in enumerate(ports_raw):
        t = get_scenario(svc_name)
        result.append({
            "id": f"R{i+1:02d}",
            "port": port_str,
            "service": svc_name,
            "scenario": t["scenario"],
            "vulnerability": t["vulnerability"],
            "asset": t["asset"],
            "consequence": t["consequence"],
            "probability": t["prob_default"],
            "impact": t["imp_default"],
            "measures": t["measures"],
            "treatment": t["treatment"],
            "status": "A traiter",
            "date": datetime.now().strftime("%d/%m/%Y"),
        })
    return result


# ==================== STYLESHEET ====================
def stylesheet():
    return f"""
    QMainWindow, QWidget {{
        background-color: {COLORS['bg']};
        color: {COLORS['text']};
        font-family: "Segoe UI", sans-serif;
        font-size: 13px;
    }}
    QTabWidget::pane {{ border: 1px solid {COLORS['border']}; border-radius: 4px; }}
    QTabBar::tab {{
        background: {COLORS['input']}; color: {COLORS['text']};
        padding: 7px 16px; border: 1px solid {COLORS['border']};
        border-bottom: none; border-radius: 4px 4px 0 0;
    }}
    QTabBar::tab:selected {{ background: {COLORS['accent']}; color: white; font-weight: bold; }}
    QTextEdit {{
        background-color: #0d1117; border: 1px solid {COLORS['border']};
        border-radius: 6px; padding: 10px;
        font-family: 'Consolas', monospace;
    }}
    QLineEdit, QComboBox, QSpinBox {{
        background-color: {COLORS['input']}; color: {COLORS['text']};
        border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 6px 10px;
    }}
    QPushButton {{
        background-color: #388bfd; color: white;
        border: none; border-radius: 6px;
        padding: 8px 14px; font-weight: 600;
    }}
    QPushButton:hover {{ background-color: {COLORS['accent']}; }}
    QPushButton:disabled {{ background-color: #30363d; color: #555; }}
    QGroupBox {{
        border: 1px solid {COLORS['border']}; border-radius: 6px;
        margin-top: 10px; padding-top: 8px;
    }}
    QGroupBox::title {{ color: {COLORS['accent']}; font-weight: bold; padding: 0 6px; }}
    QTableWidget {{
        background-color: {COLORS['input']};
        gridline-color: {COLORS['border']};
        border: 1px solid {COLORS['border']};
    }}
    QTableWidget::item {{ padding: 3px 6px; }}
    QHeaderView::section {{
        background-color: #1c2128; color: {COLORS['accent']};
        font-weight: bold; padding: 5px;
        border: 1px solid {COLORS['border']};
    }}
    QScrollArea {{ border: none; }}
    """


# ==================== MATRICE 5x5 ====================
class MatrixWidget(QWidget):
    def __init__(self, scenarios, parent=None):
        super().__init__(parent)
        self.scenarios = scenarios
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)

        title = QLabel("MATRICE DES RISQUES 5x5  (Probabilité × Impact)")
        title.setStyleSheet("font-size: 14px; font-weight: bold; color: #58a6ff;")
        lay.addWidget(title)

        note = QLabel("Les identifiants de scénarios (R01, R02...) sont positionnés dans leur cellule respective.")
        note.setStyleSheet("color: #888; font-size: 11px;")
        lay.addWidget(note)

        cells_map = {}
        for s in self.scenarios:
            key = (s["probability"], s["impact"])
            cells_map.setdefault(key, []).append(s["id"])

        def color(p, i):
            sc = p * i
            if sc >= 20: return "#7f1d1d"
            if sc >= 12: return "#c0392b"
            if sc >= 6:  return "#d97706"
            if sc >= 3:  return "#166534"
            return "#1a4731"

        PROB_ROWS = [
            (5, "Très probable (5)"),
            (4, "Probable (4)"),
            (3, "Possible (3)"),
            (2, "Peu probable (2)"),
            (1, "Rare (1)"),
        ]
        IMP_COLS = [
            (1, "Négligeable\n(1)"),
            (2, "Mineur\n(2)"),
            (3, "Modéré\n(3)"),
            (4, "Grave\n(4)"),
            (5, "Très grave\n(5)"),
        ]

        grid = QWidget()
        grid_lay = QVBoxLayout(grid)
        grid_lay.setSpacing(3)
        grid_lay.setContentsMargins(0, 0, 0, 0)

        # Header row
        hrow = QHBoxLayout()
        hrow.setSpacing(3)
        corner = QLabel("Prob. / Impact")
        corner.setFixedSize(130, 44)
        corner.setAlignment(Qt.AlignCenter)
        corner.setStyleSheet("background:#1c2128; color:#888; font-size:9px; font-weight:bold; border-radius:3px;")
        hrow.addWidget(corner)
        for _, lbl in IMP_COLS:
            l = QLabel(lbl)
            l.setFixedSize(100, 44)
            l.setAlignment(Qt.AlignCenter)
            l.setWordWrap(True)
            l.setStyleSheet("background:#1c2128; color:#aaa; font-size:9px; font-weight:bold; border-radius:3px;")
            hrow.addWidget(l)
        hw = QWidget(); hw.setLayout(hrow)
        grid_lay.addWidget(hw)

        for p_val, p_lbl in PROB_ROWS:
            row_lay = QHBoxLayout()
            row_lay.setSpacing(3)
            pl = QLabel(p_lbl)
            pl.setFixedSize(130, 62)
            pl.setAlignment(Qt.AlignCenter)
            pl.setWordWrap(True)
            pl.setStyleSheet("background:#1c2128; color:#aaa; font-size:9px; font-weight:bold; border-radius:3px;")
            row_lay.addWidget(pl)
            for i_val, _ in IMP_COLS:
                sc = p_val * i_val
                col = color(p_val, i_val)
                ids = cells_map.get((p_val, i_val), [])
                cell = QLabel()
                cell.setFixedSize(100, 62)
                cell.setAlignment(Qt.AlignCenter)
                cell.setWordWrap(True)
                ids_txt = "<br/>" + " ".join(ids) if ids else ""
                cell.setText(f"<b>{sc}</b>{ids_txt}")
                cell.setStyleSheet(f"background:{col}; color:white; font-size:11px; border-radius:4px;")
                cell.setToolTip(f"P={p_val} × I={i_val} = {sc} | Scénarios : {', '.join(ids) if ids else 'aucun'}")
                row_lay.addWidget(cell)
            rw = QWidget(); rw.setLayout(row_lay)
            grid_lay.addWidget(rw)

        lay.addWidget(grid)

        # Légende
        leg_row = QHBoxLayout()
        for txt, col in [("Très Élevé (≥20)", "#7f1d1d"), ("Élevé (12-19)", "#c0392b"),
                         ("Modéré (6-11)", "#d97706"), ("Faible (3-5)", "#166534"), ("Très Faible (1-2)", "#1a4731")]:
            b = QLabel(f"  {txt}  ")
            b.setStyleSheet(f"background:{col}; color:white; font-size:10px; border-radius:4px; padding:3px 8px;")
            leg_row.addWidget(b)
        leg_row.addStretch()
        lay.addLayout(leg_row)
        lay.addStretch()


# ==================== DIALOG ÉVALUATION MENACES ====================
class ThreatDialog(QDialog):
    def __init__(self, scenarios, parent=None):
        super().__init__(parent,
            Qt.Window |
            Qt.WindowTitleHint |
            Qt.WindowSystemMenuHint |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowMaximizeButtonHint |
            Qt.WindowCloseButtonHint
        )
        self.setWindowTitle("Évaluation des menaces – Probabilité & Impact")
        self.resize(1200, 750)
        self.setMinimumSize(900, 550)
        self.setStyleSheet(stylesheet())
        self.scenarios = [s.copy() for s in scenarios]
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)

        hdr = QLabel("Évaluez chaque scénario de risque détecté automatiquement par le scan")
        hdr.setStyleSheet("font-size: 13px; font-weight: bold; color: #58a6ff;")
        lay.addWidget(hdr)

        sub = QLabel("Ajustez Probabilité et Impact puis validez.")
        sub.setStyleSheet("color: #888; font-size: 11px;")
        lay.addWidget(sub)

        # Splitter vertical : tableau | détail
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(8)
        splitter.setStyleSheet("""
            QSplitter::handle { background: #30363d; border-radius:3px; }
            QSplitter::handle:hover { background: #58a6ff; }
        """)

        # ── Tableau ──
        self.tbl = QTableWidget(len(self.scenarios), 7)
        self.tbl.setHorizontalHeaderLabels([
            "ID", "Port / Service", "Scénario de risque (complet)",
            "Probabilité\n(1-5)", "Impact\n(1-5)", "Niveau de risque", "Statut"
        ])
        hh = self.tbl.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setStretchLastSection(True)   # Statut prend l'espace restant
        self.tbl.setWordWrap(False)       # Pas de retour à la ligne → hauteur compacte
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.verticalHeader().setDefaultSectionSize(52)  # Hauteur fixe par ligne
        self.tbl.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        self.tbl.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.tbl.setVerticalScrollMode(QTableWidget.ScrollPerPixel)

        self.prob_spins    = []
        self.imp_spins     = []
        self.status_combos = []

        for row, s in enumerate(self.scenarios):
            def mitem(txt, align=Qt.AlignLeft | Qt.AlignVCenter):
                it = QTableWidgetItem(str(txt))
                it.setTextAlignment(align)
                it.setFlags(it.flags() & ~Qt.ItemIsEditable)
                return it

            self.tbl.setItem(row, 0, mitem(s["id"], Qt.AlignCenter))
            self.tbl.setItem(row, 1, mitem(f"{s['port']}  ({s['service']})"))
            # Texte complet — Qt tronque visuellement si trop long, tooltip survol
            sc_item = mitem(s["scenario"])
            sc_item.setToolTip(s["scenario"])
            self.tbl.setItem(row, 2, sc_item)

            ps = QSpinBox(); ps.setRange(1, 5); ps.setValue(s["probability"])
            ps.setToolTip("1=Rare  2=Peu prob.  3=Possible  4=Probable  5=Très probable")
            ps.valueChanged.connect(lambda v, r=row: self._update(r))
            self.tbl.setCellWidget(row, 3, ps); self.prob_spins.append(ps)

            im = QSpinBox(); im.setRange(1, 5); im.setValue(s["impact"])
            im.setToolTip("1=Négligeable  2=Mineur  3=Modéré  4=Grave  5=Très grave")
            im.valueChanged.connect(lambda v, r=row: self._update(r))
            self.tbl.setCellWidget(row, 4, im); self.imp_spins.append(im)

            rl     = risk_level(s["probability"], s["impact"])
            sc_val = s["probability"] * s["impact"]
            ri = QTableWidgetItem(f"{risk_label_fr(rl)}\n(score: {sc_val})")
            ri.setTextAlignment(Qt.AlignCenter)
            ri.setBackground(QColor(RISK_COLORS[rl]))
            ri.setForeground(QBrush(QColor("white")))
            ri.setFlags(ri.flags() & ~Qt.ItemIsEditable)
            self.tbl.setItem(row, 5, ri)

            sc_combo = QComboBox()
            sc_combo.addItems(["A traiter", "En cours", "Traite", "Accepte", "Transfere"])
            sc_combo.setCurrentText(s.get("status", "A traiter"))
            self.tbl.setCellWidget(row, 6, sc_combo); self.status_combos.append(sc_combo)

        # Largeurs fixes proportionnelles (total ~1125px, Statut s'étire)
        self.tbl.setColumnWidth(0, 45)
        self.tbl.setColumnWidth(1, 140)
        self.tbl.setColumnWidth(2, 480)
        self.tbl.setColumnWidth(3, 105)
        self.tbl.setColumnWidth(4, 90)
        self.tbl.setColumnWidth(5, 145)
        self.tbl.setColumnWidth(6, 120)

        splitter.addWidget(self.tbl)

        # ── Zone détail ──
        detail_grp = QGroupBox("Détail complet du scénario sélectionné  (cliquez sur une ligne)")
        dl = QVBoxLayout(detail_grp)
        dl.setContentsMargins(6, 6, 6, 6)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setStyleSheet("font-family: 'Segoe UI'; font-size: 12px;")
        dl.addWidget(self.detail)
        splitter.addWidget(detail_grp)

        splitter.setSizes([420, 260])
        lay.addWidget(splitter, stretch=1)

        self.tbl.currentCellChanged.connect(self._show_detail)
        if self.scenarios:
            self.tbl.setCurrentCell(0, 0)
            self._show_detail(0, 0, -1, -1)

        # Boutons
        btn_row = QHBoxLayout()
        ok_btn  = QPushButton("✅  Valider l'évaluation")
        ok_btn.setStyleSheet("background:#166534; padding:9px 20px; font-size:13px; font-weight:bold;")
        can_btn = QPushButton("Annuler")
        can_btn.setStyleSheet("background:#555; padding:9px 16px;")
        ok_btn.clicked.connect(self._save)
        can_btn.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(can_btn)
        btn_row.addWidget(ok_btn)
        lay.addLayout(btn_row)

    def _update(self, row):
        p = self.prob_spins[row].value()
        i = self.imp_spins[row].value()
        rl = risk_level(p, i)
        it = self.tbl.item(row, 5)
        it.setText(f"{risk_label_fr(rl)}\n(score: {p*i})")
        it.setBackground(QColor(RISK_COLORS[rl]))
        self._show_detail(row, 0, row, 0)

    def _show_detail(self, r, c, pr, pc):
        if r < 0 or r >= len(self.scenarios): return
        s = self.scenarios[r]
        p = self.prob_spins[r].value()
        i = self.imp_spins[r].value()
        rl = risk_level(p, i)
        col = RISK_COLORS[rl]
        self.detail.setHtml(f"""
<b style="color:#58a6ff;">{s['id']} — {s['port']} ({s['service']})</b><br/>
<b>Scénario :</b> {s['scenario']}<br/>
<b>Vulnérabilité :</b> {s['vulnerability']}<br/>
<b>Actif :</b> {s['asset']}<br/>
<b>Conséquence :</b> {s['consequence']}<br/>
<b>Probabilité :</b> {p} – {PROB_LABELS[p]} &nbsp;|&nbsp;
<b>Impact :</b> {i} – {IMP_LABELS[i]} &nbsp;|&nbsp;
<b>Risque :</b> <span style="background:{col};color:white;padding:1px 6px;border-radius:3px;">
{risk_label_fr(rl)} (score {p*i})</span><br/>
<b>Mesures existantes :</b> {s['measures']}<br/>
<b>Plan de traitement :</b> {s['treatment'].replace(chr(10), '<br/>')}
""")

    def _save(self):
        for row, s in enumerate(self.scenarios):
            s["probability"] = self.prob_spins[row].value()
            s["impact"]      = self.imp_spins[row].value()
            s["status"]      = self.status_combos[row].currentText()
        self.accept()

    def get_scenarios(self):
        return self.scenarios


# ==================== REGISTRE DES RISQUES ====================
class RegisterWidget(QWidget):
    def __init__(self, scenarios, parent=None):
        super().__init__(parent)
        self._build(scenarios)

    def _build(self, scenarios):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        title = QLabel("REGISTRE DES RISQUES")
        title.setStyleSheet("font-size: 14px; font-weight: bold; color: #58a6ff;")
        """sub = QLabel("Toutes les colonnes sont redimensionnables (←→) et le tableau défile horizontalement.")
        sub.setStyleSheet("color: #888; font-size: 11px;")
        lay.addWidget(title)
        lay.addWidget(sub)"""

        tbl = QTableWidget(len(scenarios), 9)
        tbl.setHorizontalHeaderLabels([
            "ID", "Date", "Port / Service", "Scénario de risque",
            "Vulnérabilité", "Prob.", "Impact", "Niveau risque", "Statut"
        ])
        # Toutes les colonnes en mode Interactive (glissables ←→)
        hh = tbl.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setStretchLastSection(False)
        # Largeurs initiales généreuses pour voir le texte complet
        tbl.setColumnWidth(0, 42)
        tbl.setColumnWidth(1, 80)
        tbl.setColumnWidth(2, 120)
        tbl.setColumnWidth(3, 340)  # Scénario — large
        tbl.setColumnWidth(4, 280)  # Vulnérabilité — large
        tbl.setColumnWidth(5, 75)
        tbl.setColumnWidth(6, 65)
        tbl.setColumnWidth(7, 110)
        tbl.setColumnWidth(8, 95)
        tbl.setWordWrap(True)
        tbl.verticalHeader().setVisible(False)
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        tbl.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        STATUS_COLORS = {
            "A traiter": "#ef4444", "En cours": "#f59e0b",
            "Traite": "#3fb950", "Accepte": "#58a6ff", "Transfere": "#8b5cf6"
        }

        for row, s in enumerate(scenarios):
            rl = risk_level(s["probability"], s["impact"])

            def it(txt, align=Qt.AlignLeft | Qt.AlignVCenter):
                i = QTableWidgetItem(str(txt)); i.setTextAlignment(align); return i

            tbl.setItem(row, 0, it(s["id"], Qt.AlignCenter))
            tbl.setItem(row, 1, it(s["date"], Qt.AlignCenter))
            tbl.setItem(row, 2, it(f"{s['port']}\n({s['service']})"))
            tbl.setItem(row, 3, it(s["scenario"]))
            tbl.setItem(row, 4, it(s["vulnerability"]))
            tbl.setItem(row, 5, it(f"{s['probability']}\n{PROB_LABELS[s['probability']]}", Qt.AlignCenter))
            tbl.setItem(row, 6, it(f"{s['impact']}\n{IMP_LABELS[s['impact']]}", Qt.AlignCenter))

            ri = QTableWidgetItem(f"{risk_label_fr(rl)}\n({s['probability']*s['impact']})")
            ri.setTextAlignment(Qt.AlignCenter)
            ri.setBackground(QColor(RISK_COLORS[rl]))
            ri.setForeground(QBrush(QColor("white")))
            tbl.setItem(row, 7, ri)

            status_key = s.get("status", "A traiter")
            si = QTableWidgetItem(status_key)
            si.setTextAlignment(Qt.AlignCenter)
            si.setBackground(QColor(STATUS_COLORS.get(status_key, "#555")))
            si.setForeground(QBrush(QColor("white")))
            tbl.setItem(row, 8, si)

        tbl.resizeRowsToContents()
        lay.addWidget(tbl)


# ==================== FENÊTRE ÉVALUATION ====================
class EvalWindow(QMainWindow):
    def __init__(self, hosts_text, ports_text, n_hosts, n_ports, scenarios):
        super().__init__()
        self.setWindowTitle("Evaluation des risques – Rapport complet")
        self.resize(1200, 860)
        self.setMinimumSize(900, 640)
        self.scenarios  = scenarios
        self.n_hosts    = n_hosts
        self.n_ports    = n_ports
        self.hosts_text = hosts_text
        self.ports_text = ports_text
        self.setStyleSheet(stylesheet())

        central = QWidget()
        self.setCentralWidget(central)
        root_lay = QVBoxLayout(central)
        root_lay.setContentsMargins(14, 14, 14, 14)
        root_lay.setSpacing(6)

        # Titre fixe (ne fait pas partie du splitter)
        title = QLabel("EVALUATION DES RISQUES – RAPPORT COMPLET")
        title.setStyleSheet("font-size: 19px; font-weight: bold; color: #58a6ff;")
        root_lay.addWidget(title)

        # Splitter principal : info réseau  |  onglets
        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.setHandleWidth(8)
        main_splitter.setStyleSheet("""
            QSplitter::handle {
                background: #30363d;
                border-radius: 3px;
            }
            QSplitter::handle:hover {
                background: #58a6ff;
            }
        """)

        # ── Partie haute : Résultats du scan ──
        info_box = QGroupBox("Résultats du scan réseau")
        info_box.setStyleSheet("""
            QGroupBox { border:1px solid #30363d; border-radius:6px; margin-top:10px; padding-top:8px; }
            QGroupBox::title { color:#58a6ff; font-weight:bold; padding:0 6px; }
        """)
        info_lay = QHBoxLayout(info_box)
        info_lay.setContentsMargins(8, 4, 8, 4)

        for label_title, text in [
            (f"Hôtes actifs détectés : {n_hosts}", hosts_text),
            (f"Ports ouverts identifiés : {n_ports}", ports_text)
        ]:
            col_widget = QWidget()
            col_lay = QVBoxLayout(col_widget)
            col_lay.setContentsMargins(0, 0, 0, 0)
            col_lay.setSpacing(2)
            lbl = QLabel(f"<b>{label_title}</b>")
            lbl.setStyleSheet("color: #3fb950; font-size: 12px;")
            col_lay.addWidget(lbl)
            lines_widget = QWidget()
            lines_lay = QVBoxLayout(lines_widget)
            lines_lay.setContentsMargins(4, 0, 4, 0)
            lines_lay.setSpacing(1)
            for line in text.splitlines():
                if line.strip():
                    l = QLabel(line.strip())
                    l.setStyleSheet("color: #c9d1d9; padding-left: 10px; font-size: 12px;")
                    lines_lay.addWidget(l)
            lines_lay.addStretch()
            sc = QScrollArea()
            sc.setWidget(lines_widget)
            sc.setWidgetResizable(True)
            sc.setFrameShape(QFrame.NoFrame)
            sc.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            col_lay.addWidget(sc)
            info_lay.addWidget(col_widget)
            sep = QFrame(); sep.setFrameShape(QFrame.VLine)
            sep.setStyleSheet("color: #30363d;")
            info_lay.addWidget(sep)

        main_splitter.addWidget(info_box)

        # ── Partie basse : onglets ──
        tabs = QTabWidget()
        tabs.addTab(self._tab_risques(), "Tableau des risques")
        scroll_m = QScrollArea(); scroll_m.setWidgetResizable(True)
        scroll_m.setWidget(MatrixWidget(scenarios))
        tabs.addTab(scroll_m, "Matrice 5x5")
        scroll_r = QScrollArea(); scroll_r.setWidgetResizable(True)
        scroll_r.setWidget(RegisterWidget(scenarios))
        tabs.addTab(scroll_r, "Registre des risques")
        tabs.addTab(self._tab_scenarios(), "Scénarios détaillés")
        main_splitter.addWidget(tabs)

        # Tailles initiales : 140px pour info, reste pour les onglets
        main_splitter.setSizes([140, 680])

        root_lay.addWidget(main_splitter, stretch=1)

        # Boutons fixes en bas
        btn_row = QHBoxLayout()
        re_btn = QPushButton("Réévaluer les menaces")
        re_btn.clicked.connect(self._reevaluate)
        close_btn = QPushButton("Fermer")
        close_btn.clicked.connect(self.close)
        btn_row.addWidget(re_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        root_lay.addLayout(btn_row)

    def _tab_risques(self):
        """Onglet avec splitter vertical entre les deux tableaux."""
        outer = QWidget()
        outer_lay = QVBoxLayout(outer)
        outer_lay.setContentsMargins(6, 6, 6, 6)
        outer_lay.setSpacing(4)

        inner_splitter = QSplitter(Qt.Vertical)
        inner_splitter.setHandleWidth(8)
        inner_splitter.setStyleSheet("""
            QSplitter::handle { background: #30363d; border-radius:3px; }
            QSplitter::handle:hover { background: #e67e22; }
        """)

        # ── Bloc 1 : Éléments cibles risqués ──
        bloc1 = QWidget()
        b1_lay = QVBoxLayout(bloc1)
        b1_lay.setContentsMargins(4, 4, 4, 4)
        b1_lay.setSpacing(4)

        lbl1 = QLabel("Éléments cibles risqués")
        lbl1.setStyleSheet("font-weight:bold; color:#e67e22; font-size:13px;")
        b1_lay.addWidget(lbl1)

        # Lignes filtrées selon résultats réels
        has_ports = self.n_ports > 0
        has_hosts = self.n_hosts > 0

        rows1_all = [
            (has_ports, "Tous les ports ouverts détectés",
             "Accès non autorisé, interception de données, brute-force, ransomware"),
            (has_hosts, "Tous les hôtes actifs du réseau",
             "Surface d'attaque élargie pour attaques internes/externes"),
            (has_ports or has_hosts,
             "Services exposés (DNS, Proxy, Blackice, etc.)",
             "Vol de données, exploitation CVE, perte de confidentialité/intégrité"),
        ]
        rows1 = [(a, b) for show, a, b in rows1_all if show]

        if rows1:
            t1 = QTableWidget(len(rows1), 2)
            t1.setHorizontalHeaderLabels(["Éléments cibles risqués", "Effet du risque"])
            t1.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
            t1.horizontalHeader().setStretchLastSection(True)
            t1.setColumnWidth(0, 360)
            t1.setFont(QFont("Segoe UI", 9))
            t1.setWordWrap(True)
            t1.verticalHeader().setVisible(False)
            t1.setEditTriggers(QTableWidget.NoEditTriggers)
            t1.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
            t1.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            for i, (a, b) in enumerate(rows1):
                ai = QTableWidgetItem(a); ai.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                bi = QTableWidgetItem(b); bi.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                t1.setItem(i, 0, ai)
                t1.setItem(i, 1, bi)
            t1.resizeRowsToContents()
            b1_lay.addWidget(t1)
        else:
            b1_lay.addWidget(QLabel("Aucun hôte ni port détecté lors de ce scan."))
        inner_splitter.addWidget(bloc1)

        # ── Bloc 2 : Recommandations ──
        bloc2 = QWidget()
        b2_lay = QVBoxLayout(bloc2)
        b2_lay.setContentsMargins(4, 4, 4, 4)
        b2_lay.setSpacing(4)

        lbl2 = QLabel("Recommandations par priorité")
        lbl2.setStyleSheet("font-weight:bold; color:#e67e22; font-size:13px;")
        b2_lay.addWidget(lbl2)

        rows2_all = [
            (has_ports, "CRITIQUE",
             "Fermer tous les ports inutiles\nsudo ufw enable && sudo ufw default deny incoming",
             "Accès immédiat depuis l'extérieur"),
            (True, "HAUTE",
             "Mettre à jour tous les services\nsudo apt update && sudo apt upgrade -y | Outil : Lynis",
             "Exploitation via CVE"),
            (has_ports, "HAUTE",
             "Remplacer les protocoles non chiffrés\nSSH, SFTP, HTTPS (certbot)",
             "Interception des données en clair"),
            (True, "MOYENNE",
             "Surveillance régulière\nCron : nmap -sV chaque semaine",
             "Nouveaux ports/hôtes passent inaperçus"),
            (True, "MOYENNE",
             "Principe du moindre privilège\nufw/firewalld + règles spécifiques",
             "Un service compromis donne trop de droits"),
        ]
        rows2 = [(p, s, c) for show, p, s, c in rows2_all if show]

        t2 = QTableWidget(len(rows2), 3)
        t2.setHorizontalHeaderLabels(["Priorité", "Solution – Outil / Commande", "Conséquence si non appliquée"])
        t2.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        t2.horizontalHeader().setStretchLastSection(True)
        t2.setColumnWidth(0, 95)
        t2.setColumnWidth(1, 500)
        t2.setFont(QFont("Segoe UI", 9))
        t2.setWordWrap(True)           # ← word wrap activé pour voir le texte complet
        t2.verticalHeader().setVisible(False)
        t2.setEditTriggers(QTableWidget.NoEditTriggers)
        t2.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        t2.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        PCOLORS = {"CRITIQUE": "#ef4444", "HAUTE": "#f59e0b", "MOYENNE": "#eab308"}
        for i, (prio, sol, cons) in enumerate(rows2):
            pi = QTableWidgetItem(prio)
            pi.setBackground(QColor(PCOLORS[prio])); pi.setForeground(QBrush(QColor("white")))
            pi.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
            t2.setItem(i, 0, pi)
            si = QTableWidgetItem(sol); si.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            t2.setItem(i, 1, si)
            ci = QTableWidgetItem(cons); ci.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            t2.setItem(i, 2, ci)
        t2.resizeRowsToContents()      # ← ajuste la hauteur au contenu réel
        b2_lay.addWidget(t2)
        inner_splitter.addWidget(bloc2)

        # Tailles initiales proportionnelles
        inner_splitter.setSizes([160, 400])
        outer_lay.addWidget(inner_splitter)
        return outer

    def _tab_scenarios(self):
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)

        title = QLabel("SCÉNARIOS DE RISQUE DÉTAILLÉS")
        title.setStyleSheet("font-size: 14px; font-weight: bold; color: #58a6ff;")
        lay.addWidget(title)

        for s in self.scenarios:
            rl = risk_level(s["probability"], s["impact"])
            col = RISK_COLORS[rl]
            box = QGroupBox(f"  {s['id']} — {s['port']} ({s['service']})  |  Risque : {risk_label_fr(rl)} (score {s['probability']*s['impact']})")
            box.setStyleSheet(f"QGroupBox {{ border: 2px solid {col}; border-radius:6px; margin-top:10px; padding-top:8px; }}"
                              f"QGroupBox::title {{ color:{col}; font-weight:bold; font-size:12px; }}")
            bl = QVBoxLayout(box)
            for fname, fval in [
                ("Scénario", s["scenario"]), ("Vulnérabilité", s["vulnerability"]),
                ("Actif impacté", s["asset"]), ("Conséquence", s["consequence"]),
                ("Probabilité", f"{s['probability']} – {PROB_LABELS[s['probability']]}"),
                ("Impact", f"{s['impact']} – {IMP_LABELS[s['impact']]}"),
                ("Mesures existantes", s["measures"]),
                ("Plan de traitement", s["treatment"]),
                ("Statut", s.get("status", "A traiter")),
            ]:
                row = QHBoxLayout()
                k = QLabel(f"<b>{fname} :</b>"); k.setFixedWidth(165)
                k.setStyleSheet("color:#aaa;")
                v = QLabel(fval.replace("\n", "<br/>")); v.setWordWrap(True)
                v.setStyleSheet("color:#c9d1d9;")
                row.addWidget(k); row.addWidget(v, 1)
                bl.addLayout(row)
            lay.addWidget(box)

        lay.addStretch()
        scroll.setWidget(inner)
        return scroll

    def _reevaluate(self):
        dlg = ThreatDialog(self.scenarios, self)
        if dlg.exec_():
            self.scenarios = dlg.get_scenarios()
            self.close()


# ==================== FENÊTRE PRINCIPALE ====================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Evaluation des risques – Nmap (Sujet 1)")
        self.resize(1200, 800)
        self.thread = None
        self.last_command   = ""
        self.last_pdf_path  = None
        self.last_hosts_txt = ""
        self.last_ports_txt = ""
        self.last_n_hosts   = 0
        self.last_n_ports   = 0
        self.last_raw_ports = []
        self.last_scenarios = []
        self.eval_win       = None
        self._current_cmd   = ""
        self._build()

    def _build(self):
        self.setStyleSheet(stylesheet())
        central = QWidget()
        self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        lay.setContentsMargins(20, 20, 20, 20)

        # ── Ligne titre + bouton info ──
        title_row = QHBoxLayout()
        title = QLabel("EVALUATION DES RISQUES – SCANNER NMAP")
        title.setStyleSheet("font-size: 21px; font-weight: bold; color: #58a6ff;")
        title_row.addWidget(title)
        title_row.addStretch()

        # Bouton ? (aide / principes)
        self.btn_help = QPushButton("?")
        self.btn_help.setFixedSize(34, 34)
        self.btn_help.setToolTip("Aide – Principes et fonctionnalités")
        self.btn_help.setStyleSheet("""
            QPushButton {
                background: #1e3a5f; color: #58a6ff;
                border: 2px solid #58a6ff; border-radius: 17px;
                font-size: 16px; font-weight: bold;
            }
            QPushButton:hover { background: #58a6ff; color: white; }
        """)
        self.btn_help.clicked.connect(self._open_help)
        title_row.addWidget(self.btn_help)
        lay.addLayout(title_row)

        grp = QGroupBox("Configuration du scan")
        form = QFormLayout(grp)
        self.target_edit = QLineEdit("10.47.46.194/24")
        self.profile_combo = QComboBox()
        self.profile_combo.addItems([
            "Ping sweep rapide (-sn)",
            "Scan ports TCP (-sS)",
            "Détection de services (-sV)",
            "OS + Services complet (-sV -O)"
        ])
        self.extra_edit = QLineEdit("")
        form.addRow("Cible :", self.target_edit)
        form.addRow("Profil :", self.profile_combo)
        form.addRow("Arguments supplémentaires :", self.extra_edit)
        lay.addWidget(grp)

        self.cmd_preview = QLabel()
        self.cmd_preview.setWordWrap(True)
        self.cmd_preview.setStyleSheet(
            "background:#161b22; border:1px solid #30363d; border-radius:4px;"
            "padding:7px 12px; font-family:'Consolas',monospace; color:#c9d1d9; font-size:12px;"
        )
        lay.addWidget(self.cmd_preview)

        self.terminal = QTextEdit(); self.terminal.setReadOnly(True)
        lay.addWidget(self.terminal, stretch=1)

        self.progress = QProgressBar(); self.progress.setTextVisible(False); self.progress.setFixedHeight(5)
        lay.addWidget(self.progress)

        btns = QHBoxLayout()
        self.btn_start    = QPushButton("▶  Lancer le scan")
        self.btn_stop     = QPushButton("■  Arrêter")
        self.btn_clear    = QPushButton("Effacer")
        self.btn_reeval   = QPushButton("  Evaluer menaces")
        self.btn_eval     = QPushButton("  Evaluation complète")
        self.btn_matrix   = QPushButton("  Matrice de risques")
        self.btn_pdf      = QPushButton("📄  Ouvrir le PDF")

        self.btn_stop.setEnabled(False)
        self.btn_eval.setEnabled(False)
        self.btn_matrix.setEnabled(False)
        self.btn_pdf.setEnabled(False)
        self.btn_reeval.setEnabled(False)
        self.btn_reeval.setToolTip("Rouvrir la fenêtre d'évaluation des menaces")
        self.btn_reeval.setStyleSheet("""
            QPushButton { background:#1e4d2e; }
            QPushButton:hover { background:#166534; }
            QPushButton:disabled { background:#30363d; color:#555; }
        """)

        self.btn_start.clicked.connect(self._start)
        self.btn_stop.clicked.connect(self._stop)
        self.btn_clear.clicked.connect(lambda: self.terminal.clear())
        self.btn_reeval.clicked.connect(self._reopen_threat)
        self.btn_eval.clicked.connect(self._open_eval)
        self.btn_matrix.clicked.connect(self._open_matrix)
        self.btn_pdf.clicked.connect(self._open_pdf)

        for b in [self.btn_start, self.btn_stop, self.btn_clear,
                  self.btn_reeval, self.btn_eval, self.btn_matrix, self.btn_pdf]:
            btns.addWidget(b)
        lay.addLayout(btns)

        self.status_lbl = QLabel("Prêt")
        self.status_lbl.setStyleSheet("color:#888; font-size:12px;")
        lay.addWidget(self.status_lbl)

        for sig in [self.target_edit.textChanged,
                    self.profile_combo.currentIndexChanged,
                    self.extra_edit.textChanged]:
            sig.connect(self._update_preview)
        self._update_preview()

    def _update_preview(self):
        target = self.target_edit.text().strip()
        idx    = self.profile_combo.currentIndex()
        args   = ["-sn", "-sS", "-sV", "-sV -O"][idx]
        extra  = self.extra_edit.text().strip()
        parts  = ["nmap", args] + ([extra] if extra else []) + [target]
        cmd    = " ".join(parts)
        if any(x in args for x in ["-sS", "-O"]):
            cmd = "sudo " + cmd
        names = ["Ping sweep rapide", "Scan ports TCP", "Detection de services", "OS + Services complet"]
        self.cmd_preview.setText(f"Profil : {names[idx]}   ->   {cmd}")
        self._current_cmd = cmd

    def _start(self):
        cmd = self._current_cmd
        self.last_command = cmd
        self.terminal.clear()
        self.thread = NmapThread(cmd)
        self.thread.output.connect(self.terminal.append)
        self.thread.finished.connect(self._on_finished)
        self.thread.start()
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)
        self.status_lbl.setText("Scan en cours...")
        self.progress.setRange(0, 0)

    def _stop(self):
        if self.thread: self.thread.stop()

    def _on_finished(self, ok, msg):
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        self.progress.setRange(0, 1); self.progress.setValue(1)
        if ok:
            self._extract()
            self._gen_scenarios()
            self._threat_dialog()
            self._gen_pdf()
            self.btn_eval.setEnabled(True)
            self.btn_matrix.setEnabled(True)
            self.btn_reeval.setEnabled(True)
            self.status_lbl.setText(f"Scan terminé – {self.last_n_hosts} hôtes, {self.last_n_ports} ports détectés")
        else:
            self.status_lbl.setText(f"Erreur : {msg}")

    def _extract(self):
        raw = self.thread.raw_output
        hosts = sorted(set(re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', raw)))
        port_matches = re.findall(r'(\d+/\w+)\s+open\s+([^\n]+)', raw)
        unique = list(dict.fromkeys((p, s.strip()) for p, s in port_matches))
        self.last_hosts_txt = "\n".join(f"- {h}" for h in hosts)
        self.last_ports_txt = "\n".join(f"- {p} ({s})" for p, s in unique)
        self.last_n_hosts   = len(hosts)
        self.last_n_ports   = len(unique)
        self.last_raw_ports = unique

    def _gen_scenarios(self):
        self.last_scenarios = auto_scenarios(self.last_raw_ports)

    def _threat_dialog(self):
        if not self.last_scenarios: return
        dlg = ThreatDialog(self.last_scenarios, self)
        if dlg.exec_():
            self.last_scenarios = dlg.get_scenarios()

    def _gen_pdf(self):
        pdf_dir = os.path.expanduser("~/CyberSec_Rapports")
        os.makedirs(pdf_dir, exist_ok=True)
        path = os.path.join(pdf_dir, f"risques_nmap_{datetime.now():%Y%m%d_%H%M%S}.pdf")
        ok, result = generate_pdf(
            self.last_command,
            self.thread.raw_output if self.thread else "",
            path,
            self.last_hosts_txt, self.last_ports_txt,
            self.last_n_hosts, self.last_n_ports,
            self.last_scenarios
        )
        if ok:
            self.last_pdf_path = result
            self.btn_pdf.setEnabled(True)
            self.terminal.append(f"<span style='color:#3fb950;'>PDF genere : {result}</span>")
        else:
            self.terminal.append(f"<span style='color:#ef4444;'>Erreur PDF : {result}</span>")

    def _open_eval(self):
        if self.last_hosts_txt:
            self.eval_win = EvalWindow(
                self.last_hosts_txt, self.last_ports_txt,
                self.last_n_hosts, self.last_n_ports,
                self.last_scenarios
            )
            self.eval_win.show()

    def _open_matrix(self):
        if not self.last_scenarios: return
        dlg = QDialog(self)
        dlg.setWindowTitle("Matrice de risques 5x5")
        dlg.resize(820, 560)
        dlg.setStyleSheet(stylesheet())
        dl = QVBoxLayout(dlg)
        sc = QScrollArea(); sc.setWidgetResizable(True)
        sc.setWidget(MatrixWidget(self.last_scenarios))
        dl.addWidget(sc)
        btn = QPushButton("Fermer"); btn.clicked.connect(dlg.close)
        dl.addWidget(btn)
        dlg.exec_()

    def _open_pdf(self):
        if self.last_pdf_path and os.path.exists(self.last_pdf_path):
            subprocess.Popen(["xdg-open", self.last_pdf_path])

    def _reopen_threat(self):
        """Réouvre la fenêtre d'évaluation des menaces avec les scénarios actuels."""
        if not self.last_scenarios:
            return
        dlg = ThreatDialog(self.last_scenarios, self)
        if dlg.exec_():
            self.last_scenarios = dlg.get_scenarios()
            self.terminal.append(
                "<span style='color:#3fb950;'>✅ Évaluation des menaces mise à jour.</span>"
            )

    def _open_help(self):
        """Fenêtre d'aide – Principes et fonctionnalités de l'application."""
        dlg = QDialog(self, Qt.Window |
                      Qt.WindowTitleHint | Qt.WindowSystemMenuHint |
                      Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint |
                      Qt.WindowCloseButtonHint)
        dlg.setWindowTitle("ℹ  Aide – Principes et fonctionnalités")
        dlg.resize(800, 680)
        dlg.setStyleSheet(stylesheet())
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(20, 20, 20, 20)

        title = QLabel("GUIDE DE L'APPLICATION – ÉVALUATION DES RISQUES")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #58a6ff;")
        lay.addWidget(title)

        sub = QLabel("Sujet 1 – Outils d'évaluation des menaces et des risques en cybersécurité")
        sub.setStyleSheet("color: #888; font-size: 11px; margin-bottom: 8px;")
        lay.addWidget(sub)

        content = QTextEdit()
        content.setReadOnly(True)
        content.setStyleSheet(
            "background:#0d1117; color:#c9d1d9; font-family:'Segoe UI'; font-size:13px;"
            "border:1px solid #30363d; border-radius:6px; padding:12px;"
        )
        content.setHtml("""
<style>
  h2 { color: #58a6ff; font-size:14px; margin-top:14px; margin-bottom:4px; }
  h3 { color: #e67e22; font-size:12px; margin-top:10px; margin-bottom:3px; }
  table { border-collapse:collapse; width:100%; margin:6px 0; }
  td, th { border:1px solid #30363d; padding:5px 10px; font-size:12px; }
  th { background:#1e3a5f; color:#58a6ff; }
  tr:nth-child(even) { background:#161b22; }
  .code { font-family:Consolas,monospace; background:#161b22;
          color:#3fb950; padding:2px 6px; border-radius:3px; font-size:11px; }
  .badge-c { background:#7f1d1d; color:white; padding:1px 7px; border-radius:3px; font-size:11px; }
  .badge-e { background:#c0392b; color:white; padding:1px 7px; border-radius:3px; font-size:11px; }
  .badge-m { background:#d97706; color:white; padding:1px 7px; border-radius:3px; font-size:11px; }
  .badge-f { background:#166534; color:white; padding:1px 7px; border-radius:3px; font-size:11px; }
</style>

<h2>🎯 But de l'application</h2>
<p>Cette application est un outil d'<b>évaluation des menaces et des risques (EMR)</b> réseau.
Elle automatise l'identification des actifs exposés, la génération de scénarios de risque,
le calcul du niveau de risque et la production d'un rapport PDF complet — conformément
à la méthode EMR du cours (Sujet 1, Groupe 7).</p>

<h2>🔧 Profils de scan Nmap</h2>
<table>
  <tr><th>Profil</th><th>Commande</th><th>Résultat</th></tr>
  <tr><td>Ping sweep rapide</td><td><span class="code">nmap -sn &lt;cible&gt;</span></td><td>Hôtes actifs uniquement — aucun port</td></tr>
  <tr><td>Scan ports TCP</td><td><span class="code">sudo nmap -sS &lt;cible&gt;</span></td><td>Ports TCP ouverts (SYN scan furtif)</td></tr>
  <tr><td>Détection de services</td><td><span class="code">nmap -sV &lt;cible&gt;</span></td><td>Ports + version des services (ex : Apache 2.4)</td></tr>
  <tr><td>OS + Services complet</td><td><span class="code">sudo nmap -sV -O &lt;cible&gt;</span></td><td>Ports + services + système d'exploitation</td></tr>
</table>

<h2>📊 Workflow après un scan</h2>
<p>1. <b>Scan terminé</b> → fenêtre d'évaluation des menaces s'ouvre automatiquement<br/>
2. <b>Ajuster</b> Probabilité (1–5) et Impact (1–5) pour chaque scénario détecté<br/>
3. <b>Valider</b> → PDF généré automatiquement dans <span class="code">~/CyberSec_Rapports/</span><br/>
4. <b>Rouvrir</b> l'évaluation à tout moment via le bouton <b>🔄 Evaluer menaces</b></p>

<h2>📐 Calcul du niveau de risque</h2>
<table>
  <tr><th>Niveau</th><th>Score (P × I)</th><th>Action recommandée</th></tr>
  <tr><td><span class="badge-c">Très Élevé</span></td><td>≥ 20</td><td>Stopper immédiatement et mettre en œuvre des contrôles</td></tr>
  <tr><td><span class="badge-e">Élevé</span></td><td>12 – 19</td><td>Traiter dans le mois (plan d'urgence)</td></tr>
  <tr><td><span class="badge-m">Modéré</span></td><td>6 – 11</td><td>Traiter dans les 3–6 mois</td></tr>
  <tr><td><span class="badge-f">Faible</span></td><td>3 – 5</td><td>Surveiller périodiquement</td></tr>
  <tr><td><span class="badge-f">Très Faible</span></td><td>1 – 2</td><td>Acceptable, continuer à surveiller</td></tr>
</table>

<h2>🗺  Matrice des risques 5×5</h2>
<p>Chaque scénario est positionné dans la matrice selon <b>P × I</b>.
Les identifiants (R01, R02…) apparaissent dans leur cellule.
La couleur indique le niveau : du vert (faible) au rouge foncé (très élevé).</p>

<h2>📁 Registre des risques</h2>
<p>Tableau complet de tous les scénarios avec : ID, date, port/service, probabilité,
impact, niveau de risque, mesures existantes, plan de traitement et statut.
Colonnes redimensionnables (←→) et défilement horizontal disponible.</p>

<h2>📄 Rapport PDF – Structure</h2>
<table>
  <tr><th>Section</th><th>Contenu</th></tr>
  <tr><td>1. Sortie brute du scan</td><td>Résultat Nmap brut (style terminal)</td></tr>
  <tr><td>2. Résumé du scan</td><td>Hôtes actifs + ports ouverts identifiés</td></tr>
  <tr><td>3. Analyse et recommandations</td><td>Tableau des risques + recommandations par priorité</td></tr>
  <tr><td>4. Scénarios détaillés</td><td>Un bloc par service : scénario, vulnérabilité, plan de traitement</td></tr>
  <tr><td>5. Registre des risques</td><td>Tableau complet avec tous les champs EMR</td></tr>
  <tr><td>6. Matrice 5×5</td><td>Représentation visuelle des risques avec scénarios positionnés</td></tr>
</table>

<h2>🔄 Bouton Evaluer menaces</h2>
<p>Permet de rouvrir la fenêtre d'évaluation des menaces à tout moment après un scan
pour modifier les valeurs de probabilité, impact ou statut sans relancer le scan.</p>

<h2>💡 Conseils</h2>
<p>• Utilisez <b>Détection de services (-sV)</b> ou <b>OS + Services complet</b> pour obtenir
les scénarios les plus précis.<br/>
• Glissez les séparateurs <b>↕</b> dans la fenêtre d'évaluation pour agrandir les sections.<br/>
• Le PDF est enregistré automatiquement dans <span class="code">~/CyberSec_Rapports/</span>
avec un horodatage.</p>
""")
        lay.addWidget(content, stretch=1)

        close_btn = QPushButton("Fermer")
        close_btn.clicked.connect(dlg.close)
        lay.addWidget(close_btn)
        dlg.exec_()


# ==================== THREAD ====================
class NmapThread(QThread):
    output   = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, cmd):
        super().__init__()
        self.command = cmd
        self.raw_output = ""
        self._stop = False

    def run(self):
        self.output.emit(f"<b>[{datetime.now():%H:%M:%S}]</b> Lancement : <code>{self.command}</code><br><br>")
        try:
            proc = subprocess.Popen(
                self.command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            for line in iter(proc.stdout.readline, ''):
                if self._stop: break
                if line.strip():
                    self.raw_output += line
                    self.output.emit(line.rstrip() + "<br>")
            proc.wait()
            self.finished.emit(True, "Scan termine")
        except Exception as e:
            self.finished.emit(False, str(e))

    def stop(self):
        self._stop = True


# ==================== PDF ====================
def generate_pdf(command, raw_output, output_path,
                 hosts_text="", ports_text="", n_hosts=0, n_ports=0, scenarios=None):
    if scenarios is None:
        scenarios = []
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors as C
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable, PageBreak)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        doc = SimpleDocTemplate(output_path, pagesize=A4,
                                leftMargin=1.8*cm, rightMargin=1.8*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        st = getSampleStyleSheet()
        PW = A4[0] - 3.6*cm

        def S(name, **kw):
            return ParagraphStyle(name, parent=st['Normal'], **kw)

        small  = S('sm',   fontSize=7.5, leading=10)
        norm   = S('nm',   fontSize=9,   leading=13)
        bold9  = S('b9',   fontSize=9,   leading=12, fontName='Helvetica-Bold')
        green9 = S('g9',   fontSize=9,   leading=13, fontName='Helvetica-Bold',
                   textColor=C.HexColor("#166534"))
        h1     = S('h1p',  fontSize=13,  leading=16, fontName='Helvetica-Bold',
                   textColor=C.HexColor("#1a56db"), spaceBefore=14, spaceAfter=6)
        h2_org = S('h2o',  fontSize=11,  leading=14, fontName='Helvetica-Bold',
                   textColor=C.HexColor("#c05621"), spaceBefore=10, spaceAfter=5)
        h_ttl  = S('htt',  fontSize=18,  leading=22, fontName='Helvetica-Bold',
                   textColor=C.HexColor("#1e3a5f"))
        hdr    = S('hdr',  fontSize=8,   leading=10, fontName='Helvetica-Bold',
                   textColor=C.white, alignment=TA_CENTER)
        ctr    = S('ctr',  fontSize=7.5, leading=10, alignment=TA_CENTER)

        RCOL = {
            "Tres Eleve": C.HexColor("#7f1d1d"),
            "Eleve":      C.HexColor("#c0392b"),
            "Modere":     C.HexColor("#d97706"),
            "Faible":     C.HexColor("#166534"),
            "Tres Faible":C.HexColor("#1a4731"),
        }

        story = []

        # --- Page de garde ---
        story += [
            Paragraph("RAPPORT D'EVALUATION DES RISQUES", h_ttl),
            Paragraph("Outil : Nmap | CyberSec – Sujet 1 | Groupe 7", small),
            HRFlowable(width="100%", thickness=2, color=C.HexColor("#1a56db")),
            Spacer(1, 0.4*cm),
        ]
        small_black = S('smb', fontSize=7.5, leading=10, textColor=C.black)

        meta_data = [
            [Paragraph("Outil",    hdr), Paragraph("Nmap (Network Mapper)", small_black)],
            [Paragraph("But",      hdr), Paragraph("Identifier les actifs réseau, ports ouverts et services exposés", small_black)],
            [Paragraph("Commande", hdr), Paragraph(escape(command), small_black)],
            [Paragraph("Date",     hdr), Paragraph(datetime.now().strftime("%d/%m/%Y a %H:%M:%S"), small_black)],
            [Paragraph("Fichier",  hdr), Paragraph(output_path, small_black)],
        ]
        mt = Table(meta_data, colWidths=[3*cm, PW - 3*cm])
        mt.setStyle(TableStyle([
            ('BACKGROUND',     (0,0), (0,-1), C.HexColor("#1e3a5f")),  # col gauche toujours bleu
            ('TEXTCOLOR',      (0,0), (0,-1), C.white),                 # texte gauche toujours blanc
            ('ROWBACKGROUNDS', (1,0), (1,-1), [C.white, C.HexColor("#f0f4f8")]),  # col droite seulement
            ('GRID',           (0,0), (-1,-1), 0.5, C.grey),
            ('VALIGN',         (0,0), (-1,-1), 'TOP'),
            ('PADDING',        (0,0), (-1,-1), 6),
        ]))
        story += [mt, Spacer(1, 0.5*cm)]

        # --- Section 1 : Sortie brute ---
        story.append(Paragraph("1. SORTIE BRUTE DU SCAN", h1))
        clean = re.sub(r'<[^>]+>', '', raw_output)
        lines = [l for l in clean.splitlines() if l.strip()]
        if lines:
            sc_data = [[Paragraph(escape(l), small)] for l in lines]
            sc_t = Table(sc_data, colWidths=[PW])
            sc_t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), C.HexColor("#fafbfc")),
                ('TEXTCOLOR',  (0,0), (-1,-1), C.HexColor("#c9d1d9")),
                ('FONTNAME',   (0,0), (-1,-1), 'Courier'),
                ('FONTSIZE',   (0,0), (-1,-1), 6.5),
                ('LEADING',    (0,0), (-1,-1), 8.5),
                ('BOX',        (0,0), (-1,-1), 0.5, C.grey),
                ('PADDING',    (0,0), (-1,-1), 4),
            ]))
            story.append(sc_t)
        else:
            story.append(Paragraph("Aucune sortie enregistrée.", small))
        story.append(Spacer(1, 0.5*cm))

        # --- Section 2 : Résumé ---
        story.append(Paragraph("2. RESUME DU SCAN", h1))
        h_lines = [l.strip() for l in hosts_text.splitlines() if l.strip()]
        p_lines = [l.strip() for l in ports_text.splitlines() if l.strip()]

        h_html = (f"<b>Hotes actifs detectes : {n_hosts}</b><br/>"
                  + "<br/>".join(f'<font color="#166534">{escape(h)}</font>' for h in h_lines))
        p_html = (f"<b>Ports ouverts identifies : {n_ports}</b><br/>"
                  + "<br/>".join(f'<font color="#166534">{escape(p)}</font>' for p in p_lines))

        sum_t = Table([[Paragraph(h_html, green9), Paragraph(p_html, green9)]],
                      colWidths=[PW/2, PW/2])
        sum_t.setStyle(TableStyle([
            ('BOX',        (0,0), (-1,-1), 1,   C.HexColor("#1a56db")),
            ('INNERGRID',  (0,0), (-1,-1), 0.5, C.HexColor("#b3cce8")),
            ('BACKGROUND', (0,0), (-1,-1), C.HexColor("#eef4fb")),
            ('VALIGN',     (0,0), (-1,-1), 'TOP'),
            ('PADDING',    (0,0), (-1,-1), 10),
        ]))
        story += [sum_t, Spacer(1, 0.5*cm)]

        # --- Section 3 : Analyse ---
        story.append(Paragraph("3. ANALYSE ET RECOMMANDATIONS", h1))

        has_ports = n_ports > 0
        has_hosts = n_hosts > 0

        story.append(Paragraph("TABLEAU DES RISQUES IDENTIFIES", h2_org))
        t1d = [[Paragraph("Elements cibles risques", hdr), Paragraph("Effet du risque", hdr)]]
        if has_ports:
            t1d.append([Paragraph("Tous les ports ouverts detectes", small),
                        Paragraph("Acces non autorise, interception de donnees, brute-force, ransomware", small)])
        if has_hosts:
            t1d.append([Paragraph("Tous les hotes actifs du reseau", small),
                        Paragraph("Surface d'attaque elargie pour attaques internes/externes", small)])
        if has_ports or has_hosts:
            t1d.append([Paragraph("Services exposes (DNS, Proxy, Blackice, etc.)", small),
                        Paragraph("Vol de donnees, exploitation CVE, perte de confidentialite/integrite", small)])

        if len(t1d) > 1:
            t1 = Table(t1d, colWidths=[PW*0.42, PW*0.58])
            t1.setStyle(TableStyle([
                ('BACKGROUND',     (0,0), (-1,0), C.HexColor("#1e3a5f")),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [C.white, C.HexColor("#f0f4f8")]),
                ('GRID',           (0,0), (-1,-1), 0.5, C.grey),
                ('PADDING',        (0,0), (-1,-1), 7),
                ('VALIGN',         (0,0), (-1,-1), 'TOP'),
            ]))
            story += [t1, Spacer(1, 0.4*cm)]
        else:
            story.append(Paragraph("Aucun hote ni port detecte lors de ce scan.", small))
            story.append(Spacer(1, 0.3*cm))

        story.append(Paragraph("TABLEAU DES RECOMMANDATIONS", h2_org))
        all_prio = [
            (has_ports, "CRITIQUE", "#ef4444",
             "Fermer tous les ports inutiles<br/>sudo ufw enable &amp;&amp; sudo ufw default deny incoming",
             "Acces immediat depuis l'exterieur"),
            (True,      "HAUTE",   "#f59e0b",
             "Mettre a jour tous les services<br/>sudo apt update &amp;&amp; sudo apt upgrade -y | Outil : Lynis",
             "Exploitation via CVE"),
            (has_ports, "HAUTE",   "#f59e0b",
             "Remplacer les protocoles non chiffres<br/>SSH, SFTP, HTTPS (certbot)",
             "Interception des donnees en clair"),
            (True,      "MOYENNE", "#eab308",
             "Surveillance reguliere<br/>Cron : nmap -sV chaque semaine",
             "Nouveaux ports/hotes passent inapercus"),
            (True,      "MOYENNE", "#eab308",
             "Principe du moindre privilege<br/>ufw/firewalld + regles specifiques",
             "Un service compromis donne trop de droits"),
        ]
        prio_rows = [(p, col, sol, cons) for show, p, col, sol, cons in all_prio if show]
        t2d = [[Paragraph("Priorite", hdr), Paragraph("Solution – Outil / Commande", hdr),
                Paragraph("Consequence si non appliquee", hdr)]]
        style_cmds2 = [
            ('BACKGROUND',    (0,0),  (-1,0),  C.HexColor("#1e3a5f")),
            ('ROWBACKGROUNDS',(0,1),  (-1,-1), [C.white, C.HexColor("#f0f4f8")]),
            ('GRID',          (0,0),  (-1,-1), 0.5, C.grey),
            ('PADDING',       (0,0),  (-1,-1), 7),
            ('VALIGN',        (0,0),  (-1,-1), 'TOP'),
        ]
        for row_i, (prio, color, sol, cons) in enumerate(prio_rows, 1):
            ps = S(f'ps{row_i}', fontSize=8, leading=10, fontName='Helvetica-Bold',
                   textColor=C.white, alignment=TA_CENTER)
            t2d.append([Paragraph(prio, ps), Paragraph(sol, small), Paragraph(cons, small)])
            style_cmds2.append(('BACKGROUND', (0, row_i), (0, row_i), C.HexColor(color)))
        t2 = Table(t2d, colWidths=[2.2*cm, PW*0.54, PW*0.34])
        t2.setStyle(TableStyle(style_cmds2))
        story += [t2, PageBreak()]

        # --- Section 4 : Scénarios ---
        story.append(Paragraph("4. SCENARIOS DE RISQUE DETAILLES", h1))

        for s in scenarios:
            rl  = risk_level(s["probability"], s["impact"])
            sc  = s["probability"] * s["impact"]
            rc  = RCOL[rl]
            rlf = risk_label_fr(rl)

            sh = S(f'sh{s["id"]}', fontSize=9, leading=12, fontName='Helvetica-Bold',
                   textColor=C.white)
            hdr_tbl = Table([[Paragraph(
                f"{s['id']} — {s['port']} ({s['service']})   |   Risque : {rlf} (score {sc})", sh
            )]], colWidths=[PW])
            hdr_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), rc),
                ('PADDING',    (0,0), (-1,-1), 7),
            ]))
            story.append(hdr_tbl)

            rows = [
                ("Scenario de risque",     s["scenario"]),
                ("Vulnerabilite",          s["vulnerability"]),
                ("Actif impacte",          s["asset"]),
                ("Consequence",            s["consequence"]),
                ("Probabilite",            f"{s['probability']} – {PROB_LABELS[s['probability']]}"),
                ("Impact",                 f"{s['impact']} – {IMP_LABELS[s['impact']]}"),
                ("Mesures existantes",     s["measures"]),
                ("Plan de traitement",     s["treatment"]),
                ("Statut",                 s.get("status", "A traiter")),
            ]
            det_d = [[Paragraph(k, bold9),
                      Paragraph(escape(v).replace("\n", "<br/>"), small)]
                     for k, v in rows]
            det_t = Table(det_d, colWidths=[3.5*cm, PW - 3.5*cm])
            det_t.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),  (0,-1), C.HexColor("#f0f4f8")),
                ('ROWBACKGROUNDS',(0,0),  (-1,-1), [C.HexColor("#f0f4f8"), C.white]),
                ('GRID',          (0,0),  (-1,-1), 0.3, C.HexColor("#cccccc")),
                ('VALIGN',        (0,0),  (-1,-1), 'TOP'),
                ('PADDING',       (0,0),  (-1,-1), 6),
            ]))
            story += [det_t, Spacer(1, 0.4*cm)]

        story.append(PageBreak())

        # --- Section 5 : Registre ---
        story.append(Paragraph("5. REGISTRE DES RISQUES", h1))

        reg_cols = ["ID", "Date", "Port / Service", "Probabilite", "Impact",
                    "Niveau de risque", "Mesures existantes", "Plan de traitement", "Statut"]
        reg_d = [[Paragraph(t, hdr) for t in reg_cols]]
        for s in scenarios:
            rl  = risk_level(s["probability"], s["impact"])
            sc  = s["probability"] * s["impact"]
            rc  = RCOL[rl]
            rlf = risk_label_fr(rl)
            rls = S(f'rls{s["id"]}', fontSize=7, leading=9, fontName='Helvetica-Bold',
                    textColor=C.white, alignment=TA_CENTER)
            reg_d.append([
                Paragraph(s["id"],   small),
                Paragraph(s["date"], small),
                Paragraph(f"{s['port']}<br/>({s['service']})", small),
                Paragraph(f"{s['probability']}<br/>{PROB_LABELS[s['probability']]}", small),
                Paragraph(f"{s['impact']}<br/>{IMP_LABELS[s['impact']]}", small),
                Paragraph(f"{rlf}<br/>(score {sc})", rls),
                Paragraph(escape(s["measures"]), small),
                Paragraph(escape(s["treatment"]).replace("\n", "<br/>"), small),
                Paragraph(s.get("status", "A traiter"), small),
            ])
        cw = [0.8*cm, 1.6*cm, 2*cm, 1.8*cm, 1.5*cm, 2*cm, 2.8*cm, 3.5*cm, 1.8*cm]
        reg_t = Table(reg_d, colWidths=cw, repeatRows=1)
        reg_t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),  (-1,0),  C.HexColor("#1e3a5f")),
            ('ROWBACKGROUNDS',(0,1),  (-1,-1), [C.white, C.HexColor("#f0f4f8")]),
            ('GRID',          (0,0),  (-1,-1), 0.3, C.grey),
            ('VALIGN',        (0,0),  (-1,-1), 'TOP'),
            ('PADDING',       (0,0),  (-1,-1), 4),
        ]))
        story += [reg_t, Spacer(1, 0.4*cm)]

        # Couleurs risque dans col 5
        for row_i, s in enumerate(scenarios, 1):
            rl = risk_level(s["probability"], s["impact"])
            reg_t.setStyle(TableStyle([('BACKGROUND', (5, row_i), (5, row_i), RCOL[rl])]))

        story.append(PageBreak())

        # --- Section 6 : Matrice 5x5 ---
        story.append(Paragraph("6. MATRICE DES RISQUES 5x5", h1))
        story.append(Paragraph("Score de risque = Probabilite × Impact. Les identifiants de scenarios sont positionnés dans leur cellule.", small))
        story.append(Spacer(1, 0.3*cm))

        def ccolor(p, i):
            s = p * i
            if s >= 20: return C.HexColor("#7f1d1d")
            if s >= 12: return C.HexColor("#c0392b")
            if s >= 6:  return C.HexColor("#d97706")
            if s >= 3:  return C.HexColor("#166534")
            return C.HexColor("#1a4731")

        cmap = {}
        for s in scenarios:
            cmap.setdefault((s["probability"], s["impact"]), []).append(s["id"])

        IMP_S = ["Neg.(1)", "Min.(2)", "Mod.(3)", "Grave(4)", "T.grav(5)"]
        PRB_S = ["T.prob.(5)", "Prob.(4)", "Poss.(3)", "P.prob(2)", "Rare(1)"]
        cw_m  = (PW - 2.5*cm) / 5
        cs    = S('cs', fontSize=7, leading=9, textColor=C.white, alignment=TA_CENTER)
        csh   = S('csh', fontSize=7, leading=9, fontName='Helvetica-Bold', textColor=C.white, alignment=TA_CENTER)

        mat_h = [Paragraph("P \\ I", csh)] + [Paragraph(t, csh) for t in IMP_S]
        mat_d = [mat_h]
        for p_v in range(5, 0, -1):
            row_d = [Paragraph(PRB_S[5 - p_v], csh)]
            for i_v in range(1, 6):
                sc = p_v * i_v
                ids = cmap.get((p_v, i_v), [])
                txt = f"<b>{sc}</b>" + (f"<br/>{'  '.join(ids)}" if ids else "")
                row_d.append(Paragraph(txt, cs))
            mat_d.append(row_d)

        mat_t = Table(mat_d, colWidths=[2.5*cm] + [cw_m]*5)
        mat_cmds = [
            ('BACKGROUND', (0,0), (-1,0), C.HexColor("#1e3a5f")),
            ('BACKGROUND', (0,0), (0,-1), C.HexColor("#1e3a5f")),
            ('GRID',       (0,0), (-1,-1), 0.5, C.HexColor("#444")),
            ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
            ('PADDING',    (0,0), (-1,-1), 5),
        ]
        for ri, pv in enumerate(range(5, 0, -1), 1):
            for ci, iv in enumerate(range(1, 6), 1):
                mat_cmds.append(('BACKGROUND', (ci, ri), (ci, ri), ccolor(pv, iv)))
        mat_t.setStyle(TableStyle(mat_cmds))
        story.append(mat_t)

        story.append(Spacer(1, 0.3*cm))
        leg_d = [[Paragraph(t, S(f'l{i}', fontSize=7, leading=9, textColor=C.white,
                                  alignment=TA_CENTER, backColor=col))
                  for i, (t, col) in enumerate([
                    ("Tres Eleve (>=20)", C.HexColor("#7f1d1d")),
                    ("Eleve (12-19)",     C.HexColor("#c0392b")),
                    ("Modere (6-11)",     C.HexColor("#d97706")),
                    ("Faible (3-5)",      C.HexColor("#166534")),
                    ("Tres Faible (1-2)", C.HexColor("#1a4731")),
                  ])]]
        leg_t = Table(leg_d, colWidths=[PW/5]*5)
        leg_t.setStyle(TableStyle([('PADDING', (0,0), (-1,-1), 5)]))
        story.append(leg_t)

        doc.build(story)
        return True, output_path

    except Exception as e:
        import traceback
        return False, traceback.format_exc()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()