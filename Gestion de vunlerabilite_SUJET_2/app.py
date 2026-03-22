#!/usr/bin/env python3
# ============================================================
#  SUJET 2 — GESTION DES VULNÉRABILITÉS
#  Module Vulnérabilités · OpenVAS · Nikto · Analyse rapport
#  Application PyQt5 professionnelle
#  Palette : Blanc / Vert (success) / Noir
#  Compatible : Kali Linux / Ubuntu — Python 3.8+
# ============================================================

import sys
import subprocess
import os
import re
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QFrame,
    QScrollArea, QStackedWidget, QProgressBar, QComboBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPalette


# ──────────────────────────────────────────────
#  PALETTE DE COULEURS
# ──────────────────────────────────────────────
C = {
    "bg_main":        "#0A0E1A",
    "bg_card":        "#111827",
    "bg_sidebar":     "#0D1424",
    "bg_input":       "#1A2035",
    "blue_primary":   "#3B6CF4",
    "blue_light":     "#5B8AF5",
    "blue_dark":      "#2451C4",
    "blue_glow":      "#1E3A8A",
    "white":          "#FFFFFF",
    "white_80":       "#CCDDFF",
    "white_60":       "#8899CC",
    "white_40":       "#4A5568",
    "border":         "#1E2D4A",
    "border_blue":    "#2451C4",
    "success":        "#10B981",  # Vert principal pour ce module
    "success_light":  "#34D399",
    "success_dark":   "#059669",
    "success_glow":   "#064E3B",
    "warning":        "#F59E0B",
    "danger":         "#EF4444",
    "text_primary":   "#F0F6FF",
    "text_secondary": "#8899CC",
    "purple":         "#A855F7",
}


# ──────────────────────────────────────────────
#  GÉNÉRATEUR PDF AUTOMATIQUE
# ──────────────────────────────────────────────
def generate_pdf_report(module_name, command, raw_output, output_path):
    """
    Génère automatiquement un rapport PDF après l'exécution d'un module.
    Capture la sortie brute du terminal et produit un fichier PDF structuré.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors as rl_colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, HRFlowable)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        # ── Palette couleurs pour module Vulnérabilités (vert) ──────────────
        hdr_col, acc_col, bg_col = ("#1A5276", "#27AE60", "#EAFAF1")

        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )
        styles = getSampleStyleSheet()
        story  = []

        # ── Styles ────────────────────────────────────────────────────────────
        title_s = ParagraphStyle('T', parent=styles['Title'],
                                  fontSize=18, alignment=TA_CENTER,
                                  textColor=rl_colors.HexColor(hdr_col),
                                  spaceAfter=4)
        h1 = ParagraphStyle('H1', parent=styles['Heading1'],
                              fontSize=12, textColor=rl_colors.HexColor(hdr_col),
                              spaceBefore=10, spaceAfter=4,
                              backColor=rl_colors.HexColor(bg_col), borderPad=4)
        h2 = ParagraphStyle('H2', parent=styles['Heading2'],
                              fontSize=10, textColor=rl_colors.HexColor(acc_col),
                              spaceBefore=6, spaceAfter=3)
        normal = ParagraphStyle('N', parent=styles['Normal'],
                                 fontSize=9, leading=13)
        small  = ParagraphStyle('S', parent=styles['Normal'],
                                 fontSize=8, leading=12)
        code_s = ParagraphStyle('C', parent=styles['Code'],
                                 fontSize=8, leading=12,
                                 backColor=rl_colors.HexColor('#1C2833'),
                                 textColor=rl_colors.HexColor('#00FF7F'),
                                 leftIndent=8, rightIndent=8, borderPad=6)
        footer_s = ParagraphStyle('F', parent=small,
                                   alignment=TA_CENTER,
                                   textColor=rl_colors.HexColor('#888888'))

        # ── En-tête ───────────────────────────────────────────────────────────
        story.append(Paragraph(f"RAPPORT — {module_name.upper()}", title_s))
        story.append(Paragraph("CyberSec Tool — FAFA12 | Rapport automatique post-exécution",
                                ParagraphStyle('Sub', parent=small, alignment=TA_CENTER,
                                               textColor=rl_colors.HexColor('#888888'))))
        story.append(HRFlowable(width="100%", thickness=2,
                                 color=rl_colors.HexColor(hdr_col)))
        story.append(Spacer(1, 0.3*cm))

        meta = [
            ["Module",    module_name],
            ["Commande",  command],
            ["Date",      datetime.now().strftime("%d/%m/%Y  %H:%M:%S")],
            ["Rapport",   output_path],
        ]
        mt = Table(meta, colWidths=[3.5*cm, 12.5*cm])
        mt.setStyle(TableStyle([
            ('BACKGROUND',  (0, 0), (0, -1), rl_colors.HexColor(hdr_col)),
            ('TEXTCOLOR',   (0, 0), (0, -1), rl_colors.white),
            ('FONTNAME',    (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME',    (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE',    (0, 0), (-1, -1), 8.5),
            ('ROWBACKGROUNDS', (1, 0), (1, -1),
             [rl_colors.HexColor(bg_col), rl_colors.white]),
            ('GRID',  (0, 0), (-1, -1), 0.4, rl_colors.HexColor('#BDC3C7')),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(mt)
        story.append(Spacer(1, 0.4*cm))

        # ── Sortie brute du terminal ──────────────────────────────────────────
        story.append(Paragraph("1. Sortie de l'outil (terminal)", h1))
        story.append(Paragraph("Commande exécutée :", h2))
        story.append(Paragraph(command, code_s))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph("Résultat complet :", h2))

        # Nettoyer les balises HTML du terminal Qt
        clean = re.sub(r'<[^>]+>', '', raw_output)
        clean = clean.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')

        # Découper en lignes et coloriser
        lines = [l.rstrip() for l in clean.split('\n') if l.strip()]
        if not lines:
            lines = ["(Aucune sortie capturée)"]

        for line in lines[:200]:   # max 200 lignes dans le PDF
            lo = line.lower()
            if any(w in lo for w in ['error', 'erreur', 'failed', 'critical', 'CRITIQUE']):
                tc = rl_colors.HexColor('#E74C3C')
            elif any(w in lo for w in ['warning', 'warn', 'avertissement']):
                tc = rl_colors.HexColor('#E67E22')
            elif any(w in lo for w in ['open', 'found', 'detected', 'ok', 'succes', 'pass', 'vuln']):
                tc = rl_colors.HexColor('#27AE60')
            elif any(w in lo for w in ['info', 'note', 'suggestion']):
                tc = rl_colors.HexColor('#2980B9')
            else:
                tc = rl_colors.HexColor('#2C3E50')
            story.append(Paragraph(
                line.replace('<', '&lt;').replace('>', '&gt;'),
                ParagraphStyle('L', parent=small, textColor=tc,
                               fontName='Courier', spaceAfter=1)
            ))

        if len(lines) > 200:
            story.append(Paragraph(
                f"... {len(lines)-200} lignes supplémentaires (voir terminal)",
                ParagraphStyle('More', parent=small,
                               textColor=rl_colors.HexColor('#888888'),
                               fontName='Helvetica-Oblique')))

        story.append(Spacer(1, 0.4*cm))

        # ── Analyse et recommandations pour Vulnérabilités ────────────────────
        story.append(Paragraph("2. Analyse et Interprétation", h1))
        analysis, recommendations = _get_analysis(module_name, command, clean)
        story.append(Paragraph(analysis, normal))
        story.append(Spacer(1, 0.3*cm))

        story.append(Paragraph("3. Recommandations", h1))
        for i, rec in enumerate(recommendations, 1):
            prio, text = rec
            pc = ('#C0392B' if prio == 'CRITIQUE' else
                  '#E67E22' if prio == 'HAUTE' else
                  '#F1C40F' if prio == 'MOYENNE' else '#27AE60')
            row = Table([[
                Paragraph(f"<b>{prio}</b>",
                           ParagraphStyle('RP', parent=small, textColor=rl_colors.white,
                                          fontName='Helvetica-Bold', alignment=TA_CENTER)),
                Paragraph(f"{i}. {text}", normal),
            ]], colWidths=[2.5*cm, 13.5*cm])
            row.setStyle(TableStyle([
                ('BACKGROUND',  (0, 0), (0, 0), rl_colors.HexColor(pc)),
                ('PADDING',     (0, 0), (-1, -1), 5),
                ('BOX',         (0, 0), (-1, -1), 0.5, rl_colors.HexColor(pc)),
                ('VALIGN',      (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID',        (0, 0), (-1, -1), 0.3, rl_colors.HexColor('#D5D8DC')),
            ]))
            story.append(row)
            story.append(Spacer(1, 0.15*cm))

        # ── Pied de page ──────────────────────────────────────────────────────
        story.append(Spacer(1, 0.4*cm))
        story.append(HRFlowable(width="100%", thickness=1,
                                 color=rl_colors.HexColor('#BDC3C7')))
        story.append(Paragraph(
            f"Généré automatiquement le {datetime.now().strftime('%d/%m/%Y à %H:%M')} "
            f"par CyberSec Tool — FAFA12  |  Module : {module_name}",
            footer_s))

        doc.build(story)
        return True, output_path

    except Exception as e:
        return False, str(e)


def _get_analysis(module_name, command, output_text):
    """Retourne (texte_analyse, liste_recommandations) pour le module Vulnérabilités."""

    # Analyse pour outils de vulnérabilités (Nikto, OpenVAS, Nmap NSE, WhatWeb)
    vulns = re.findall(r'(?:OSVDB|CVE|vuln|Vuln|vulnerability|Vulnerability)[^\n]*', output_text)
    n_vulns = len(vulns)

    # Compter aussi les problèmes de sécurité détectés
    issues = re.findall(r'(?:Issue|Problem|Finding|Alert|Risk|High|Medium|Critical)[^\n]*', output_text, re.I)

    analysis = (
        f"L'analyse de vulnérabilités a identifié <b>{n_vulns} vulnérabilité(s) référencée(s)</b> "
        f"et <b>{len(issues)} problème(s) de sécurité détecté(s)</b>. "
        "Le cycle de gestion des vulnérabilités (découverte → classification → correction → "
        "vérification) doit être appliqué immédiatement sur les éléments détectés. "
        "Prioriser selon le score CVSS : critique (≥9.0), élevé (7.0-8.9), moyen (4.0-6.9). "
        "Les vulnérabilités web identifiées par Nikto nécessitent une revue de code et "
        "une mise à jour des composants concernés."
    )

    recs = [
        ("CRITIQUE", "Appliquer immédiatement les correctifs pour les CVE critiques (CVSS ≥ 9.0)."),
        ("HAUTE",    "Relancer le scan après chaque correction pour valider l'élimination."),
        ("HAUTE",    "Désactiver les modules/services inutiles identifiés par l'outil."),
        ("MOYENNE",  "Intégrer les scans de vulnérabilité dans le pipeline CI/CD."),
        ("MOYENNE",  "Mettre en place une veille CVE (https://nvd.nist.gov) pour les technologies utilisées."),
        ("FAIBLE",   "Documenter chaque vulnérabilité dans un registre de suivi avec état de correction."),
    ]

    # Alertes spécifiques selon l'outil utilisé
    if "nikto" in command.lower():
        if "xss" in output_text.lower() or "cross" in output_text.lower():
            recs.insert(0, ("CRITIQUE", "Vulnérabilités XSS détectées — implémenter l'encodage de sortie et CSP."))
        if "sql" in output_text.lower() or "injection" in output_text.lower():
            recs.insert(0, ("CRITIQUE", "Injection SQL détectée — utiliser des requêtes paramétrées immédiatement."))
        if "outdated" in output_text.lower() or "old" in output_text.lower():
            recs.insert(0, ("HAUTE", "Logiciels obsolètes détectés — planifier la mise à jour des composants."))

    if "openvas" in command.lower() or "gvm" in command.lower():
        recs.insert(0, ("HAUTE", "Configurer OpenVAS pour des scans réguliers automatiques (cron hebdomadaire)."))

    if "whatweb" in command.lower():
        recs.insert(0, ("MOYENNE", "Masquer les bannières de version des serveurs web détectés."))

    return analysis, recs[:7]


def make_global_style():
    bg   = C["bg_main"]
    txt  = C["text_primary"]
    card = C["bg_card"]
    inp  = C["bg_input"]
    bp   = C["blue_primary"]
    bl   = C["blue_light"]
    bd   = C["blue_dark"]
    wh   = C["white"]
    return (
        "QMainWindow, QWidget {"
        "  background-color: " + bg + ";"
        "  color: " + txt + ";"
        "  font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;"
        "  font-size: 14px;"
        "}"
        "QScrollBar:vertical {"
        "  background: " + card + "; width: 6px; border-radius: 3px;"
        "}"
        "QScrollBar::handle:vertical {"
        "  background: " + C["success"] + "; border-radius: 3px; min-height: 30px;"
        "}"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }"
        "QScrollBar:horizontal {"
        "  background: " + card + "; height: 6px; border-radius: 3px;"
        "}"
        "QScrollBar::handle:horizontal {"
        "  background: " + C["success"] + "; border-radius: 3px;"
        "}"
        "QToolTip {"
        "  background-color: " + card + "; color: " + wh + ";"
        "  border: 1px solid " + C["success"] + "; border-radius: 6px; padding: 6px 10px; font-size: 13px;"
        "}"
        "QProgressBar {"
        "  background-color: " + inp + "; border: none; border-radius: 4px; height: 6px;"
        "}"
        "QProgressBar::chunk {"
        "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "    stop:0 " + C["success_dark"] + ", stop:1 " + C["success_light"] + ");"
        "  border-radius: 4px;"
        "}"
    )


def combo_style(hover_color):
    bg   = C["bg_input"]
    txt  = C["text_primary"]
    brd  = C["border"]
    card = C["bg_card"]
    return (
        "QComboBox {"
        "  background-color: " + bg + ";"
        "  color: " + txt + ";"
        "  border: 1px solid " + brd + ";"
        "  border-radius: 8px;"
        "  padding: 8px 14px;"
        "  font-size: 13px;"
        "}"
        "QComboBox:hover { border-color: " + hover_color + "; }"
        "QComboBox::drop-down { border: none; width: 30px; }"
        "QComboBox QAbstractItemView {"
        "  background: " + card + ";"
        "  color: " + txt + ";"
        "  border: 1px solid " + hover_color + ";"
        "  border-radius: 8px;"
        "  selection-background-color: " + hover_color + ";"
        "}"
    )


# ──────────────────────────────────────────────
#  THREAD D'EXÉCUTION
# ──────────────────────────────────────────────
class CommandThread(QThread):
    output_signal   = pyqtSignal(str)
    finished_signal = pyqtSignal(bool)
    progress_signal = pyqtSignal(int)

    def __init__(self, command, parent=None):
        super().__init__(parent)
        self.command    = command
        self._running   = True
        self.raw_output = ""

    def run(self):
        ts  = datetime.now().strftime("%H:%M:%S")
        col = C["success_light"]
        self.output_signal.emit(
            "<span style='color:" + col + ";'>"
            "<br>[" + ts + "] Exécution : " + self.command + "</span><br>"
        )
        self.progress_signal.emit(10)

        try:
            process = subprocess.Popen(
                self.command, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            progress = 10
            for line in iter(process.stdout.readline, ""):
                if not self._running:
                    process.terminate()
                    break
                stripped = line.rstrip()
                if stripped:
                    self.raw_output += stripped + "\n"
                    self.output_signal.emit(self._colorize(stripped) + "<br>")
                    if progress < 90:
                        progress += 2
                        self.progress_signal.emit(progress)

            process.wait()
            self.progress_signal.emit(100)
            self.finished_signal.emit(process.returncode == 0)

        except FileNotFoundError:
            tool = self.command.split()[0]
            msg  = f"[ERREUR] Outil '{tool}' non trouvé.\nInstallez-le : sudo apt install {tool}"
            self.raw_output += msg
            self.output_signal.emit(
                "<span style='color:" + C["danger"] + ";'>"
                + msg.replace("\n", "<br>") + "</span><br>"
            )
            self.finished_signal.emit(False)

        except Exception as e:
            msg = f"[ERREUR] {str(e)}"
            self.raw_output += msg
            self.output_signal.emit(
                "<span style='color:" + C["danger"] + ";'>"
                + msg + "</span><br>"
            )
            self.finished_signal.emit(False)

    def _colorize(self, line):
        lo = line.lower()
        if any(w in lo for w in ["error", "erreur", "failed", "critical"]):
            color = C["danger"]
        elif any(w in lo for w in ["warning", "warn"]):
            color = C["warning"]
        elif any(w in lo for w in ["vuln", "found", "detected", "open", "ok", "pass"]):
            color = C["success"]
        elif any(w in lo for w in ["info", "suggestion", "note"]):
            color = C["success_light"]
        else:
            color = C["text_primary"]
        return "<span style='color:" + color + ";'>" + line + "</span>"

    def stop(self):
        self._running = False


# ──────────────────────────────────────────────
#  COMPOSANTS UI
# ──────────────────────────────────────────────

class GlowButton(QPushButton):
    def __init__(self, text, icon_char="", primary=True, accent_color=None, parent=None):
        super().__init__(parent)
        self.setText(("  " + icon_char + "  " + text) if icon_char else text)

        # Couleur d'accentuation (vert par défaut pour ce module)
        if accent_color is None:
            accent_color = C["success"]

        acc_dark = C["success_dark"]
        acc_light = C["success_light"]
        acc_glow = C["success_glow"]
        wh = C["white"]
        w4 = C["white_40"]
        w6 = C["white_60"]

        if primary:
            self.setStyleSheet(
                "QPushButton {"
                "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                "    stop:0 " + acc_dark + ", stop:1 " + accent_color + ");"
                "  color: " + wh + "; border: none; border-radius: 10px;"
                "  padding: 12px 24px; font-size: 14px; font-weight: 600;"
                "}"
                "QPushButton:hover {"
                "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                "    stop:0 " + accent_color + ", stop:1 " + acc_light + ");"
                "}"
                "QPushButton:pressed { background: " + acc_dark + "; }"
                "QPushButton:disabled { background:" + w4 + "; color:" + w6 + "; }"
            )
        else:
            self.setStyleSheet(
                "QPushButton {"
                "  background: transparent; color: " + acc_light + ";"
                "  border: 1px solid " + accent_color + "; border-radius: 10px;"
                "  padding: 10px 20px; font-size: 13px; font-weight: 500;"
                "}"
                "QPushButton:hover { background: " + acc_glow + "; border-color: " + acc_light + "; }"
                "QPushButton:pressed { background: " + acc_dark + "; }"
            )
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(42)


class InputField(QLineEdit):
    def __init__(self, placeholder="", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        bg  = C["bg_input"]
        txt = C["text_primary"]
        brd = C["border"]
        acc = C["success"]
        w4  = C["white_40"]
        self.setStyleSheet(
            "QLineEdit {"
            "  background-color: " + bg + "; color: " + txt + ";"
            "  border: 1px solid " + brd + "; border-radius: 10px;"
            "  padding: 10px 16px; font-size: 14px;"
            "  selection-background-color: " + acc + ";"
            "}"
            "QLineEdit:focus { border-color: " + acc + "; background-color: #1E2A42; }"
            "QLineEdit:hover { border-color: " + w4 + "; }"
        )
        self.setMinimumHeight(42)


class OutputTerminal(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        txt = C["text_primary"]
        brd = C["border"]
        self.setStyleSheet(
            "QTextEdit {"
            "  background-color: #080C15; color: " + txt + ";"
            "  border: 1px solid " + brd + "; border-radius: 12px;"
            "  padding: 16px;"
            "  font-family: 'Courier New', 'Consolas', monospace; font-size: 13px;"
            "}"
        )
        self.setMinimumHeight(280)
        # Message bienvenue
        col1 = C["success_light"]
        col2 = C["white"]
        col3 = C["text_secondary"]
        self.setHtml(
            "<span style='color:" + col1 + "; font-family:monospace;'>"
            "┌─────────────────────────────────────────────┐<br>"
            "│ <span style='color:" + col2 + "; font-weight:bold;'>"
            "GESTION DES VULNÉRABILITÉS — Terminal</span> │<br>"
            "│ <span style='color:" + col3 + ";'>"
            "Prêt à scanner les vulnérabilités...</span>   │<br>"
            "└─────────────────────────────────────────────┘"
            "</span>"
        )

    def append_html(self, html):
        cursor = self.textCursor()
        cursor.movePosition(cursor.End)
        self.setTextCursor(cursor)
        self.insertHtml(html)
        cursor.movePosition(cursor.End)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def clear_output(self):
        self.clear()
        ts  = datetime.now().strftime("%H:%M:%S")
        col = C["white_60"]
        self.append_html(
            "<span style='color:" + col + ";'>[" + ts + "] Terminal effacé.</span><br>"
        )


class SectionCard(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._set_style(False)

    def _set_style(self, highlighted):
        brd = C["success"] if highlighted else C["border"]
        bg  = C["bg_card"]
        self.setStyleSheet(
            "QFrame {"
            "  background-color: " + bg + ";"
            "  border: 1px solid " + brd + ";"
            "  border-radius: 14px; padding: 4px;"
            "}"
        )

    def set_highlighted(self, on):
        self._set_style(on)


# ──────────────────────────────────────────────
#  MODULE 2 — GESTION DES VULNÉRABILITÉS
# ──────────────────────────────────────────────
class VulnModule(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.title       = "Gestion de vulnérabilité"
        self.subtitle    = "OpenVAS · Nikto · Analyse rapport · Plan de remédiation"
        self.accent      = C["success"]
        self.thread      = None
        self._last_cmd   = ""
        self._last_pdf   = ""
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)

        # En-tête
        header  = QWidget()
        h_lay   = QHBoxLayout(header)
        h_lay.setContentsMargins(0, 0, 0, 0)
        t_block = QVBoxLayout()
        t_block.setSpacing(4)

        t_lbl = QLabel(self.title)
        t_lbl.setStyleSheet(
            "font-size:22px; font-weight:700; color:" + C["white"] + "; letter-spacing:-0.3px;"
        )
        s_lbl = QLabel(self.subtitle)
        s_lbl.setStyleSheet("font-size:13px; color:" + C["text_secondary"] + ";")
        t_block.addWidget(t_lbl)
        t_block.addWidget(s_lbl)

        badge = QLabel("● ACTIF")
        badge.setStyleSheet(
            "color:" + self.accent + "; font-size:11px; font-weight:700; letter-spacing:1px;"
        )
        h_lay.addLayout(t_block)
        h_lay.addStretch()
        h_lay.addWidget(badge, alignment=Qt.AlignTop)
        layout.addWidget(header)

        # Séparateur
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:" + C["border"] + "; border:none; max-height:1px;")
        layout.addWidget(sep)

        # Card de configuration
        self.config_card   = SectionCard()
        self.config_layout = QVBoxLayout(self.config_card)
        self.config_layout.setContentsMargins(20, 16, 20, 16)
        self.config_layout.setSpacing(14)
        self._build_config()
        layout.addWidget(self.config_card)

        # Barre de progression
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setStyleSheet(
            "QProgressBar { background:" + C["bg_input"] + "; border:none; border-radius:3px; }"
            "QProgressBar::chunk {"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "    stop:0 " + C["success_dark"] + ", stop:1 " + C["success_light"] + ");"
            "  border-radius:3px;"
            "}"
        )
        layout.addWidget(self.progress_bar)

        # Label terminal
        tlbl = QLabel("  Terminal de sortie")
        tlbl.setStyleSheet(
            "font-size:12px; font-weight:600; color:" + C["white_60"] + ";"
            " background:" + C["bg_card"] + "; padding:8px 16px;"
            " border-radius:8px 8px 0 0;"
            " border:1px solid " + C["border"] + "; border-bottom:none;"
        )
        layout.addWidget(tlbl)

        # Terminal
        self.terminal = OutputTerminal()
        layout.addWidget(self.terminal, stretch=1)

        # Boutons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.run_btn   = GlowButton("Lancer l'analyse", "▶", primary=True, accent_color=C["success"])
        self.stop_btn  = GlowButton("Arrêter", "■", primary=False, accent_color=C["success"])
        self.clear_btn = GlowButton("Effacer", "X", primary=False, accent_color=C["success"])
        self.pdf_btn   = GlowButton("Ouvrir rapport PDF", "⬇", primary=False, accent_color=C["success"])

        self.stop_btn.setEnabled(False)
        self.pdf_btn.setEnabled(False)

        self.run_btn.clicked.connect(self.run_analysis)
        self.stop_btn.clicked.connect(self.stop_analysis)
        self.clear_btn.clicked.connect(self.terminal.clear_output)
        self.pdf_btn.clicked.connect(self._open_pdf)

        btn_row.addWidget(self.run_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addWidget(self.clear_btn)
        btn_row.addWidget(self.pdf_btn)
        btn_row.addStretch()

        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet("color:" + C["white_60"] + "; font-size:12px;")
        btn_row.addWidget(self.status_lbl)
        layout.addLayout(btn_row)

    def _build_config(self):
        row1 = QHBoxLayout()
        row1.setSpacing(10)
        row1.addWidget(self._config_label("Cible HTTP/IP :"))
        self.target_input = InputField("ex: 192.168.1.10  ou  http://cible.local")
        self.target_input.setText("192.168.1.10")
        row1.addWidget(self.target_input)
        self.config_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(10)
        row2.addWidget(self._config_label("Outil :"))
        self.tool_combo = QComboBox()
        self.tool_combo.addItems([
            "Nikto  — Scanner Web vulnérabilités",
            "OpenVAS  — Démarrer le service GVM",
            "Nmap NSE  — Scripts vulnérabilités",
            "WhatWeb  — Identification technologies",
        ])
        self.tool_combo.setStyleSheet(combo_style(C["success"]))
        row2.addWidget(self.tool_combo)
        self.config_layout.addLayout(row2)

        self.config_layout.addWidget(
            self._info_label("Requis :  sudo apt install nikto gvm whatweb")
        )

    def run_analysis(self):
        target = self.target_input.text().strip()
        if not target:
            self.status_lbl.setText("Entrez une cible.")
            return
        idx = self.tool_combo.currentIndex()
        cmds = {
            0: "nikto -h " + target,
            1: "sudo gvm-start && echo 'OpenVAS démarré sur https://127.0.0.1:9392'",
            2: "sudo nmap --script vuln,exploit -sV " + target,
            3: "whatweb -v " + target,
        }
        self._start_thread(cmds.get(idx, "nikto -h " + target))

    def stop_analysis(self):
        if self.thread and self.thread.isRunning():
            self.thread.stop()
            self.thread.wait()
            self._on_finished(False)
            self.status_lbl.setText("Arrêté par l'utilisateur")

    def _start_thread(self, command):
        self._last_cmd = command
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.pdf_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_lbl.setText("En cours...")
        self.config_card.set_highlighted(True)

        self.thread = CommandThread(command)
        self.thread.output_signal.connect(self.terminal.append_html)
        self.thread.finished_signal.connect(self._on_finished)
        self.thread.progress_signal.connect(self.progress_bar.setValue)
        self.thread.start()

    def _on_finished(self, success):
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.config_card.set_highlighted(False)
        ts = datetime.now().strftime("%H:%M:%S")

        if success:
            self.status_lbl.setText("Terminé — " + ts)
            self.terminal.append_html(
                "<br><span style='color:" + C["success"] + "; font-weight:bold;'>"
                "✔ Analyse terminée avec succès</span><br>"
            )
        else:
            self.status_lbl.setText("Terminé avec erreurs — " + ts)

        # Génération automatique du PDF
        raw = self.thread.raw_output if self.thread else ""
        ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', self.title.lower())
        pdf_dir = os.path.expanduser("~/CyberSec_Rapports")
        os.makedirs(pdf_dir, exist_ok=True)
        pdf_path = os.path.join(pdf_dir, f"rapport_{safe_name}_{ts_file}.pdf")

        self.terminal.append_html(
            "<br><span style='color:" + C["success_light"] + ";'>"
            "⚙  Génération du rapport PDF en cours...</span><br>"
        )

        ok, result = generate_pdf_report(self.title, self._last_cmd, raw, pdf_path)

        if ok:
            self._last_pdf = result
            self.pdf_btn.setEnabled(True)
            self.terminal.append_html(
                "<span style='color:" + C["success"] + "; font-weight:bold;'>"
                "📄 Rapport PDF généré : " + result + "</span><br>"
            )
            self.status_lbl.setText("PDF prêt — " + ts)
        else:
            self.terminal.append_html(
                "<span style='color:" + C["warning"] + ";'>"
                "⚠ PDF non généré (reportlab manquant ?) : " + result + "<br>"
                "→ Installez : pip install reportlab --break-system-packages"
                "</span><br>"
            )

    def _open_pdf(self):
        """Ouvre le dernier rapport PDF avec le visionneur système."""
        if self._last_pdf and os.path.exists(self._last_pdf):
            for viewer in ["xdg-open", "evince", "okular", "eog"]:
                try:
                    subprocess.Popen([viewer, self._last_pdf],
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
                    self.terminal.append_html(
                        "<span style='color:" + C["success_light"] + ";'>"
                        "📂 Ouverture : " + self._last_pdf + "</span><br>"
                    )
                    return
                except FileNotFoundError:
                    continue
            self.terminal.append_html(
                "<span style='color:" + C["warning"] + ";'>"
                "Rapport disponible ici : " + self._last_pdf + "</span><br>"
            )

    def _config_label(self, text):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "color:" + C["white_80"] + "; font-weight:600; min-width:140px;"
        )
        return lbl

    def _info_label(self, text):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "color:" + C["text_secondary"] + "; font-size:12px; font-style:italic;"
        )
        return lbl


# ──────────────────────────────────────────────
#  FENÊTRE PRINCIPALE
# ──────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberSec Tool — Sujet 2: Gestion des Vulnérabilités")
        self.setMinimumSize(1000, 680)
        self.resize(1280, 800)
        self.setStyleSheet(make_global_style())
        self._build_ui()
        self._center()

    def _center(self):
        screen = QApplication.primaryScreen().geometry()
        g = self.geometry()
        self.move(
            (screen.width()  - g.width())  // 2,
            (screen.height() - g.height()) // 2,
        )

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Sidebar
        sidebar = self._build_sidebar()
        root.addWidget(sidebar)

        # Module principal
        scroll = QScrollArea()
        self.vuln_module = VulnModule()
        scroll.setWidget(self.vuln_module)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea { background:" + C["bg_main"] + "; border:none; }"
        )
        root.addWidget(scroll, stretch=1)

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setFixedWidth(260)
        sidebar.setStyleSheet(
            "QFrame {"
            "  background-color:" + C["bg_sidebar"] + ";"
            "  border-right:1px solid " + C["border"] + ";"
            "}"
        )
        lay = QVBoxLayout(sidebar)
        lay.setContentsMargins(16, 20, 16, 20)
        lay.setSpacing(6)

        # Logo
        logo = QFrame()
        logo.setStyleSheet(
            "QFrame {"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
            "    stop:0 " + C["success_dark"] + ", stop:1 " + C["success_glow"] + ");"
            "  border-radius:12px; border:none;"
            "}"
        )
        llay = QVBoxLayout(logo)
        llay.setContentsMargins(16, 14, 16, 14)
        llay.setSpacing(2)

        icon_l = QLabel("🛡️")
        icon_l.setStyleSheet("font-size:24px; font-weight:900; color:" + C["white"] + "; background:transparent;")
        title_l = QLabel("Vulnérabilités")
        title_l.setStyleSheet(
            "font-size:16px; font-weight:800; color:" + C["white"] + ";"
            " letter-spacing:-0.3px; background:transparent;"
        )
        sub_l = QLabel("Sujet 2 — FAFA12")
        sub_l.setStyleSheet(
            "font-size:11px; color:" + C["white_80"] + "; background:transparent;"
        )
        llay.addWidget(icon_l)
        llay.addWidget(title_l)
        llay.addWidget(sub_l)
        lay.addWidget(logo)

        # Description du module
        lay.addSpacing(20)
        desc = QLabel(
            "Ce module permet de détecter et gérer les vulnérabilités "
            "de sécurité sur les systèmes et applications web."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(
            "color:" + C["text_secondary"] + "; font-size:12px; line-height:1.4;"
        )
        lay.addWidget(desc)

        lay.addStretch()

        # Séparateur
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:" + C["border"] + "; border:none; max-height:1px;")
        lay.addWidget(sep)
        lay.addSpacing(8)

        # Outils
        info = QLabel("Outils intégrés :")
        info.setStyleSheet("color:" + C["white_60"] + "; font-size:11px; font-weight:600;")
        lay.addWidget(info)

        for tool, desc_text in [
            ("nikto", "Scanner Web"),
            ("openvas/gvm", "Vulnérabilités"),
            ("nmap NSE", "Scripts avancés"),
            ("whatweb", "Fingerprinting"),
        ]:
            row = QHBoxLayout()
            d = QLabel("-")
            d.setStyleSheet("color:" + C["success_light"] + "; font-size:13px; min-width:12px;")
            t = QLabel(tool)
            t.setStyleSheet("color:" + C["text_primary"] + "; font-size:12px; font-family:monospace;")
            ds = QLabel(desc_text)
            ds.setStyleSheet("color:" + C["text_secondary"] + "; font-size:11px;")
            row.addWidget(d)
            row.addWidget(t)
            row.addWidget(ds)
            row.addStretch()
            lay.addLayout(row)

        lay.addSpacing(10)
        ver = QLabel("v1.0  PyQt5  Python 3")
        ver.setStyleSheet("color:" + C["white_40"] + "; font-size:10px;")
        lay.addWidget(ver, alignment=Qt.AlignHCenter)
        return sidebar


# ──────────────────────────────────────────────
#  POINT D'ENTRÉE
# ──────────────────────────────────────────────
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
