
from PyQt5 import QtCore, QtWidgets, QtGui
from pathlib import Path
import json
import sqlite3
import time

from config.config_manager import load_config
from core.correlator import run_full_scan
from report.report_builder import build_html_report
from ui.styles import stylesheet_for
from ui.settings_window import SettingsWidget

from ui.overlays import ScanGridOverlay
from ui.about_dialog import AboutDialog, DEV_1, DEV_2
from ui.icons import get_icon

APP_VERSION = "1.0.0"

class PortfolioWorker(QtCore.QThread):
    progressed = QtCore.pyqtSignal(int, str)
    per_target_done = QtCore.pyqtSignal(dict)
    finished_ok = QtCore.pyqtSignal(list)

    def __init__(self, targets):
        super().__init__()
        self.targets = targets

    def run(self):
        cfg = load_config()
        results = []
        n = max(1, len(self.targets))

        for i, t in enumerate(self.targets, start=1):
            self.progressed.emit(int((i-1)/n*100), f"Scanning {t} ({i}/{n})")
            res = run_full_scan(
                cfg, t,
                progress_cb=lambda p, m: self.progressed.emit(int((i-1)/n*100 + p/n), f"{t}: {m}")
            )
            res["report_html"] = build_html_report(res)
            results.append(res)
            self.per_target_done.emit(res)

        self.progressed.emit(100, "Portfolio scan complete")
        self.finished_ok.emit(results)

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AmanScan — Security Exposure Intelligence")
        self.resize(1280, 820)

        self.scan_results = []
        self.current_report_html = ""

        self.apply_theme(load_config().ui_theme)

        root = QtWidgets.QWidget()
        root_l = QtWidgets.QHBoxLayout(root)
        root_l.setContentsMargins(14, 14, 14, 14)
        root_l.setSpacing(14)
        self.setCentralWidget(root)

        self.nav = QtWidgets.QListWidget()
        pages = ["Dashboard", "Scan", "Findings", "Report", "Trend", "Settings"]
        self.nav.addItems(pages)
        self.nav.setFixedWidth(220)
        self.nav.currentRowChanged.connect(self.on_nav)

       
        for i in range(self.nav.count()):
            item = self.nav.item(i)
            name = item.text()
            item.setIcon(get_icon(name, size=18))

        root_l.addWidget(self.nav)

        right = QtWidgets.QVBoxLayout()
        right.setSpacing(14)
        root_l.addLayout(right, 1)

       
        header = QtWidgets.QFrame()
        header.setObjectName("HeaderFrame")
        hl = QtWidgets.QHBoxLayout(header)
        hl.setContentsMargins(14, 12, 14, 12)
        hl.setSpacing(14)

        title_box = QtWidgets.QVBoxLayout()
        self.lbl_title = QtWidgets.QLabel("AmanScan — Security Exposure Intelligence")
        self.lbl_title.setObjectName("TitleLabel")

        self.lbl_sub = QtWidgets.QLabel("Passive OSINT • Defensive Reporting • Product-grade Risk Model")
        self.lbl_sub.setObjectName("SubTitleLabel")

       
        self.lbl_devs = QtWidgets.QLabel(f"Developed by {DEV_1} • {DEV_2}")
        self.lbl_devs.setObjectName("DevLabel")

        title_box.addWidget(self.lbl_title)
        title_box.addWidget(self.lbl_sub)
        title_box.addWidget(self.lbl_devs)
        hl.addLayout(title_box, 1)

        self.lbl_status = QtWidgets.QLabel("Ready.")
        self.lbl_status.setObjectName("SubTitleLabel")
        hl.addWidget(self.lbl_status)

        self.btn_about = QtWidgets.QPushButton("About")
        self.btn_about.clicked.connect(self.show_about)
        hl.addWidget(self.btn_about)

        right.addWidget(header)

       
        self.panel = QtWidgets.QFrame()
        self.panel.setObjectName("Panel")
        self.panel.setProperty("active", True)
        panel_l = QtWidgets.QVBoxLayout(self.panel)
        panel_l.setContentsMargins(14, 14, 14, 14)
        panel_l.setSpacing(14)
        right.addWidget(self.panel, 1)

        self.inner_stack = QtWidgets.QStackedWidget()
        panel_l.addWidget(self.inner_stack, 1)

        
        self.page_dashboard = self._build_dashboard()
        self.page_scan = self._build_scan()
        self.page_findings = self._build_findings()
        self.page_report = self._build_report()
        self.page_trend = self._build_trend()
        self.page_settings = SettingsWidget(on_theme_changed=self.apply_theme)

        self.pages = [self.page_dashboard, self.page_scan, self.page_findings, self.page_report, self.page_trend, self.page_settings]
        for p in self.pages:
            self.inner_stack.addWidget(p)

       
        self._glow = QtWidgets.QGraphicsDropShadowEffect(self)
        self._glow.setBlurRadius(28)
        self._glow.setOffset(0, 0)
        self._glow.setColor(QtGui.QColor(35, 184, 255, 120))
        self.panel.setGraphicsEffect(self._glow)

        
        self.overlay = ScanGridOverlay(self)
        self.overlay.raise_()
        self.overlay.set_enabled(True)

        self.nav.setCurrentRow(0)

    def resizeEvent(self, e: QtGui.QResizeEvent):
        super().resizeEvent(e)
        if self.overlay:
            self.overlay.setGeometry(self.rect())

    def apply_theme(self, theme_name: str):
        # Keep window stylesheet (OK)
        self.setStyleSheet(stylesheet_for(theme_name))
        # Also apply globally so dialogs match
        app = QtWidgets.QApplication.instance()
        if app is not None:
            app.setStyleSheet(stylesheet_for(theme_name))

    def show_about(self):
        dlg = AboutDialog(self, version=APP_VERSION)
        dlg.exec_()

    def on_nav(self, idx: int):
        if idx < 0:
            return
        self.inner_stack.setCurrentIndex(idx)
        
        if idx == 1:  # Scan
            self._glow.setColor(QtGui.QColor(35, 184, 255, 145))
            self._glow.setBlurRadius(30)
        else:
            self._glow.setColor(QtGui.QColor(35, 184, 255, 120))
            self._glow.setBlurRadius(28)

    

    def _build_dashboard(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)
        l.setSpacing(14)

        self.d_kpis = QtWidgets.QTextBrowser()
        self.d_kpis.setPlaceholderText("Run a scan to populate the dashboard KPIs...")
        l.addWidget(self.d_kpis, 1)

        self.d_ai = QtWidgets.QTextBrowser()
        self.d_ai.setPlaceholderText("AI Executive Summary will appear here after scan (defensive only).")
        l.addWidget(self.d_ai, 1)

        return w

    def _build_scan(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)
        l.setSpacing(14)

        box = QtWidgets.QGroupBox("Targets (one per line) — Multi-asset Portfolio Scan")
        form = QtWidgets.QVBoxLayout(box)

        self.targets_in = QtWidgets.QPlainTextEdit()
        self.targets_in.setPlaceholderText("example.com\nhttps://example.org\n1.2.3.4")
        self.targets_in.setFixedHeight(120)
        form.addWidget(self.targets_in)

        btn_row = QtWidgets.QHBoxLayout()
        self.btn_scan = QtWidgets.QPushButton("Start Portfolio Scan")
        self.btn_scan.clicked.connect(self.start_scan)

        self.btn_stop = QtWidgets.QPushButton("Stop")
        self.btn_stop.setDisabled(True)
        self.btn_stop.clicked.connect(self.stop_scan)

        self.btn_grid = QtWidgets.QPushButton("Toggle HUD Grid")
        self.btn_grid.clicked.connect(self.toggle_grid)

        btn_row.addWidget(self.btn_scan)
        btn_row.addWidget(self.btn_stop)
        btn_row.addWidget(self.btn_grid)
        btn_row.addStretch(1)
        form.addLayout(btn_row)

        l.addWidget(box)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setValue(0)
        l.addWidget(self.progress)

        self.logs = QtWidgets.QTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setPlaceholderText("Logs...")
        l.addWidget(self.logs, 1)

        return w

    def _build_findings(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)
        self.findings = QtWidgets.QTextBrowser()
        self.findings.setPlaceholderText("Findings will appear here after scan.")
        l.addWidget(self.findings, 1)
        return w

    def _build_report(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)
        l.setSpacing(10)

        btn_row = QtWidgets.QHBoxLayout()
        self.btn_export_html = QtWidgets.QPushButton("Export HTML (Current)")
        self.btn_export_json = QtWidgets.QPushButton("Export JSON (Portfolio)")
        self.btn_export_pdf = QtWidgets.QPushButton("Export PDF (Current)")
        for b in (self.btn_export_html, self.btn_export_json, self.btn_export_pdf):
            b.setDisabled(True)

        self.btn_export_html.clicked.connect(self.export_html)
        self.btn_export_json.clicked.connect(self.export_json)
        self.btn_export_pdf.clicked.connect(self.export_pdf)

        btn_row.addWidget(self.btn_export_html)
        btn_row.addWidget(self.btn_export_pdf)
        btn_row.addWidget(self.btn_export_json)
        btn_row.addStretch(1)
        l.addLayout(btn_row)

        self.report_preview = QtWidgets.QTextBrowser()
        self.report_preview.setPlaceholderText("Report HTML will appear here after scan.")
        l.addWidget(self.report_preview, 1)
        return w

    def _build_trend(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)
        l.setSpacing(10)

        row = QtWidgets.QHBoxLayout()
        self.tr_target = QtWidgets.QComboBox()
        self.tr_btn_refresh = QtWidgets.QPushButton("Refresh Trend")
        self.tr_btn_refresh.clicked.connect(self.refresh_trend)

        row.addWidget(QtWidgets.QLabel("Target:"))
        row.addWidget(self.tr_target, 1)
        row.addWidget(self.tr_btn_refresh)
        l.addLayout(row)

        self.tr_table = QtWidgets.QTableWidget(0, 7)
        self.tr_table.setHorizontalHeaderLabels(["Time", "IP", "Exposure", "OverallRisk", "TopCVSS", "KEV", "Critical/High"])
        self.tr_table.horizontalHeader().setStretchLastSection(True)
        l.addWidget(self.tr_table, 1)

        self.refresh_trend()
        return w

    
    def toggle_grid(self):
        if not self.overlay:
            return
        self.overlay.set_enabled(not self.overlay.isVisible())

   
    def log(self, msg: str):
        self.logs.append(msg)

    def start_scan(self):
        raw = self.targets_in.toPlainText().strip()
        targets = [x.strip() for x in raw.splitlines() if x.strip()]
        if not targets:
            QtWidgets.QMessageBox.warning(self, "AmanScan", "Enter at least one target (one per line).")
            return

        self.btn_scan.setDisabled(True)
        self.btn_stop.setDisabled(False)

        self.progress.setValue(0)
        self.logs.clear()
        self.findings.clear()
        self.report_preview.clear()
        self.d_kpis.clear()
        self.d_ai.clear()

        self.scan_results = []
        self.current_report_html = ""
        self.lbl_status.setText("Starting portfolio scan...")

        self._glow.setColor(QtGui.QColor(35, 184, 255, 165))
        self._glow.setBlurRadius(34)

        self.worker = PortfolioWorker(targets)
        self.worker.progressed.connect(self.on_progress)
        self.worker.per_target_done.connect(self.on_target_done)
        self.worker.finished_ok.connect(self.on_done)
        self.worker.start()

    def stop_scan(self):
        try:
            if hasattr(self, "worker") and self.worker.isRunning():
                self.worker.terminate()
        except Exception:
            pass
        self.btn_scan.setDisabled(False)
        self.btn_stop.setDisabled(True)
        self.lbl_status.setText("Stopped.")
        self._glow.setColor(QtGui.QColor(35, 184, 255, 120))
        self._glow.setBlurRadius(28)

    def on_progress(self, p: int, msg: str):
        self.progress.setValue(max(0, min(100, int(p))))
        self.lbl_status.setText(msg)
        self.log(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def on_target_done(self, res: dict):
        self.scan_results.append(res)
        self._render_findings_for(res)
        self._render_report_for(res)
        self._render_dashboard_for(res)

    def on_done(self, results: list):
        self.btn_scan.setDisabled(False)
        self.btn_stop.setDisabled(True)

        if self.current_report_html:
            self.btn_export_html.setDisabled(False)
            self.btn_export_pdf.setDisabled(False)
        if self.scan_results:
            self.btn_export_json.setDisabled(False)

        self.lbl_status.setText("Done.")
        self.refresh_trend()

        self._glow.setColor(QtGui.QColor(35, 184, 255, 120))
        self._glow.setBlurRadius(28)

    
    def _render_dashboard_for(self, res: dict):
        host = res.get("host","")
        ip = res.get("ip","")
        rs = res.get("risk_summary") or {}
        counts = (rs.get("counts") or {})
        exposure = rs.get("exposure_hint_0_15")
        overall = rs.get("overall_risk_0_100", 0)

        txt = []
        txt.append(f"<b>Target:</b> {host} ({ip})<br>")
        txt.append(f"<b>Overall Risk:</b> {overall}/100<br>")
        txt.append(f"<b>Exposure:</b> {exposure}/15<br>")
        txt.append(f"<b>CVEs:</b> {len(res.get('cves') or [])}<br>")
        txt.append(f"<b>Critical/High/Med:</b> {counts.get('Critical',0)}/{counts.get('High',0)}/{counts.get('Medium',0)}<br>")
        prof = res.get("profiles") or {}
        txt.append("<hr>")
        txt.append("<b>System Profile:</b><br>")
        txt.append(f"Web: {prof.get('web')} • Remote: {prof.get('remote_access')} • DB: {prof.get('databases')} • AdminPanels: {prof.get('admin_panels')}<br>")
        txt.append(f"Sensitive Ports: {prof.get('sensitive_ports',[])}<br>")
        self.d_kpis.setHtml("".join(txt))

        ai = res.get("ai_analysis") or {}
        if ai.get("text_ar"):
            self.d_ai.setPlainText(ai.get("text_ar",""))
        else:
            self.d_ai.setPlainText(f"AI not available: {ai.get('_error','')}")

    def _render_findings_for(self, res: dict):
        host = res.get("host","")
        ip = res.get("ip","")
        cves = res.get("cves", []) or []
        exp = res.get("exploit_intel", {}) or {}
        nvd = res.get("nvd", {}) or {}

        lines = []
        if res.get("error"):
            lines.append(f"ERROR: {res.get('error')}")
        else:
            rs = res.get("risk_summary") or {}
            counts = (rs.get("counts") or {})
            lines.append("AmanScan Results (Portfolio Item)")
            lines.append(f"Target: {host} ({ip})")
            lines.append(f"Generated: {res.get('generated_at','')}")
            lines.append(f"Overall Risk: {rs.get('overall_risk_0_100',0)}/100 | Exposure: {rs.get('exposure_hint_0_15','')}/15")
            lines.append("")
            lines.append(f"CVEs (passive): {len(cves)} | Critical/High: {counts.get('Critical',0)}/{counts.get('High',0)}")
            lines.append("")
            lines.append("Top CVEs (Risk/Severity/Confidence/CVSS):")
            top_sorted = sorted(cves, key=lambda c: int((exp.get(c) or {}).get('risk_score') or 0), reverse=True)[:10]
            for c in top_sorted:
                e = exp.get(c, {}) or {}
                cvss = ((nvd.get(c, {}) or {}).get("cvss") or {}).get("baseScore")
                lines.append(f"- {c}: risk={e.get('risk_score')} sev={e.get('severity')} conf={e.get('confidence')} cvss={cvss} :: {e.get('final_status')}")
        self.findings.setPlainText("\n".join(lines))

    def _render_report_for(self, res: dict):
        html = res.get("report_html","") or ""
        self.current_report_html = html
        if html:
            self.report_preview.setHtml(html)
        else:
            self.report_preview.setPlainText("No report generated.")

    
    def export_html(self):
        html = self.current_report_html
        if not html:
            return
        fn, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save HTML Report",
            f"AmanScan_Report_{time.strftime('%Y%m%d_%H%M%S')}.html",
            "HTML (*.html)"
        )
        if not fn:
            return
        Path(fn).write_text(html, encoding="utf-8")
        QtWidgets.QMessageBox.information(self, "AmanScan", f"Saved:\n{fn}")

    def export_json(self):
        if not self.scan_results:
            return
        fn, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save JSON (Portfolio)",
            f"AmanScan_Portfolio_{time.strftime('%Y%m%d_%H%M%S')}.json",
            "JSON (*.json)"
        )
        if not fn:
            return
        Path(fn).write_text(json.dumps(self.scan_results, ensure_ascii=False, indent=2), encoding="utf-8")
        QtWidgets.QMessageBox.information(self, "AmanScan", f"Saved:\n{fn}")

    def export_pdf(self):
        html = self.current_report_html
        if not html:
            return
        fn, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save PDF Report",
            f"AmanScan_Report_{time.strftime('%Y%m%d_%H%M%S')}.pdf",
            "PDF (*.pdf)"
        )
        if not fn:
            return

        from PyQt5.QtPrintSupport import QPrinter
        doc = QtGui.QTextDocument()
        doc.setHtml(html)
        pr = QPrinter(QPrinter.HighResolution)
        pr.setOutputFormat(QPrinter.PdfFormat)
        pr.setOutputFileName(fn)
        pr.setPageMargins(12, 12, 12, 12, QPrinter.Millimeter)
        doc.print_(pr)
        QtWidgets.QMessageBox.information(self, "AmanScan", f"Saved:\n{fn}")

    
    def refresh_trend(self):
        cfg = load_config()
        db = cfg.history_db_path
        Path(db).parent.mkdir(parents=True, exist_ok=True)

        targets = []
        try:
            con = sqlite3.connect(db)
            try:
                con.execute("""
                  CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    target TEXT NOT NULL,
                    host TEXT,
                    ip TEXT,
                    exposure_hint INTEGER,
                    risk_overall INTEGER,
                    top_cvss REAL,
                    kev_count INTEGER,
                    critical_count INTEGER,
                    high_count INTEGER,
                    medium_count INTEGER,
                    low_count INTEGER,
                    info_count INTEGER
                  )
                """)
                rows = con.execute("SELECT DISTINCT target FROM scan_history ORDER BY target").fetchall()
                targets = [r[0] for r in rows if r and r[0]]
            finally:
                con.close()
        except Exception:
            targets = []

        cur = self.tr_target.currentText().strip()
        self.tr_target.blockSignals(True)
        self.tr_target.clear()
        self.tr_target.addItems(targets)
        if cur and cur in targets:
            self.tr_target.setCurrentText(cur)
        self.tr_target.blockSignals(False)

        target = self.tr_target.currentText().strip()
        self.tr_table.setRowCount(0)
        if not target:
            return

        try:
            con = sqlite3.connect(db)
            try:
                rows = con.execute("""
                  SELECT ts, ip, exposure_hint, risk_overall, top_cvss, kev_count, critical_count, high_count
                  FROM scan_history
                  WHERE target=?
                  ORDER BY ts DESC
                  LIMIT 50
                """, (target,)).fetchall()
            finally:
                con.close()
        except Exception:
            rows = []

        self.tr_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            ts, ip, exposure, overall, topcvss, kev, crit, high = r
            tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            vals = [tstr, str(ip or ""), str(exposure or 0), str(overall or 0), str(topcvss or 0), str(kev or 0), f"{crit or 0}/{high or 0}"]
            for j, v in enumerate(vals):
                it = QtWidgets.QTableWidgetItem(v)
                it.setFlags(it.flags() ^ QtCore.Qt.ItemIsEditable)
                self.tr_table.setItem(i, j, it)

def run_app():
    app = QtWidgets.QApplication([])

    
    cfg = load_config()
    app.setStyleSheet(stylesheet_for(cfg.ui_theme))

    w = MainWindow()
    w.show()
    app.exec_()
