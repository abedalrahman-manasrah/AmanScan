
from PyQt5 import QtWidgets
import requests

from config.config_manager import load_config, save_config, mask
from core.zoomeye_client import ZoomEye
from ui.styles import stylesheet_for

class SettingsWidget(QtWidgets.QWidget):
    def __init__(self, parent=None, on_theme_changed=None):
        super().__init__(parent)
        self.cfg = load_config()
        self.on_theme_changed = on_theme_changed

        layout = QtWidgets.QVBoxLayout(self)

        box = QtWidgets.QGroupBox("API Keys & Plugins (stored locally, not in code)")
        form = QtWidgets.QFormLayout(box)

        self.in_shodan = QtWidgets.QLineEdit(mask(self.cfg.shodan_api_key))
        self.in_zoomeye = QtWidgets.QLineEdit(mask(self.cfg.zoomeye_api_key))
        self.in_openai = QtWidgets.QLineEdit(mask(self.cfg.openai_api_key))
        self.in_openai_model = QtWidgets.QLineEdit(self.cfg.openai_model or "gpt-5")
        self.in_github = QtWidgets.QLineEdit(mask(self.cfg.github_token))
        self.in_webcheck = QtWidgets.QLineEdit(self.cfg.webcheck_base_url)
        self.in_nvd = QtWidgets.QLineEdit(mask(self.cfg.nvd_api_key))

        for x in [self.in_shodan, self.in_zoomeye, self.in_openai, self.in_github, self.in_nvd]:
            x.setEchoMode(QtWidgets.QLineEdit.Password)

        
        self.cb_webcheck = QtWidgets.QCheckBox("Enable Web-Check")
        self.cb_shodan = QtWidgets.QCheckBox("Enable Shodan")
        self.cb_zoomeye = QtWidgets.QCheckBox("Enable ZoomEye")
        self.cb_nvd = QtWidgets.QCheckBox("Enable NVD (CVSS)")
        self.cb_ai = QtWidgets.QCheckBox("Enable AI Analysis")

        self.cb_webcheck.setChecked(bool(self.cfg.enable_webcheck))
        self.cb_shodan.setChecked(bool(self.cfg.enable_shodan))
        self.cb_zoomeye.setChecked(bool(self.cfg.enable_zoomeye))
        self.cb_nvd.setChecked(bool(self.cfg.enable_nvd))
        self.cb_ai.setChecked(bool(self.cfg.enable_ai))

        self.theme = QtWidgets.QComboBox()
        self.theme.addItems(["hud_dark", "classic_blue"])
        self.theme.setCurrentText(self.cfg.ui_theme or "hud_dark")

        form.addRow("Shodan API Key", self.in_shodan)
        form.addRow("ZoomEye API Key", self.in_zoomeye)
        form.addRow("OpenAI API Key", self.in_openai)
        form.addRow("OpenAI Model", self.in_openai_model)
        form.addRow("GitHub Token (optional)", self.in_github)
        form.addRow("Web-Check API Base URL", self.in_webcheck)
        form.addRow("NVD API Key (optional)", self.in_nvd)

        form.addRow("Theme", self.theme)

        form.addRow(self.cb_webcheck)
        form.addRow(self.cb_shodan)
        form.addRow(self.cb_zoomeye)
        form.addRow(self.cb_nvd)
        form.addRow(self.cb_ai)

        layout.addWidget(box)

        row = QtWidgets.QHBoxLayout()
        self.btn_save = QtWidgets.QPushButton("Save Settings")
        self.btn_test = QtWidgets.QPushButton("Test Keys")
        self.btn_save.clicked.connect(self.save)
        self.btn_test.clicked.connect(self.test)
        row.addWidget(self.btn_save)
        row.addWidget(self.btn_test)
        row.addStretch(1)
        layout.addLayout(row)

        self.out = QtWidgets.QTextEdit()
        self.out.setReadOnly(True)
        self.out.setPlaceholderText("Test output...")
        layout.addWidget(self.out, 1)

    def _read_secret(self, field: QtWidgets.QLineEdit, current: str) -> str:
        raw = field.text().strip()
        if not raw:
            return ""
        if "*" in raw:
            return current
        return raw

    def save(self):
        cfg = load_config()
        cfg.shodan_api_key = self._read_secret(self.in_shodan, cfg.shodan_api_key)
        cfg.zoomeye_api_key = self._read_secret(self.in_zoomeye, cfg.zoomeye_api_key)
        cfg.openai_api_key = self._read_secret(self.in_openai, cfg.openai_api_key)
        cfg.openai_model = (self.in_openai_model.text().strip() or cfg.openai_model or "gpt-5")
        cfg.github_token = self._read_secret(self.in_github, cfg.github_token)
        cfg.webcheck_base_url = self.in_webcheck.text().strip() or cfg.webcheck_base_url
        cfg.nvd_api_key = self._read_secret(self.in_nvd, cfg.nvd_api_key)

        cfg.enable_webcheck = self.cb_webcheck.isChecked()
        cfg.enable_shodan = self.cb_shodan.isChecked()
        cfg.enable_zoomeye = self.cb_zoomeye.isChecked()
        cfg.enable_nvd = self.cb_nvd.isChecked()
        cfg.enable_ai = self.cb_ai.isChecked()

        cfg.ui_theme = self.theme.currentText().strip() or "hud_dark"

        save_config(cfg)
        self.cfg = cfg

        self.in_shodan.setText(mask(cfg.shodan_api_key))
        self.in_zoomeye.setText(mask(cfg.zoomeye_api_key))
        self.in_openai.setText(mask(cfg.openai_api_key))
        self.in_github.setText(mask(cfg.github_token))
        self.in_nvd.setText(mask(cfg.nvd_api_key))

        
        if self.on_theme_changed:
            self.on_theme_changed(cfg.ui_theme)

        QtWidgets.QMessageBox.information(self, "AmanScan", "Settings saved to ~/.config/amanscan/config.json")

    def test(self):
        cfg = load_config()
        out = []

        
        if cfg.shodan_api_key:
            try:
                r = requests.get("https://api.shodan.io/api-info", params={"key": cfg.shodan_api_key}, timeout=15)
                out.append(f"Shodan: HTTP {r.status_code} (api-info)")
            except Exception as e:
                out.append(f"Shodan: ERROR {e}")
        else:
            out.append("Shodan: missing key")

        
        if cfg.zoomeye_api_key:
            try:
                zm = ZoomEye(api_key=cfg.zoomeye_api_key)
                res = zm.search_ip("8.8.8.8", page=1, pagesize=1)
                hits = res.hits()
                out.append("ZoomEye: OK (v2/search)")
                out.append(f"  hits_returned: {len(hits)}")
            except Exception as e:
                out.append(f"ZoomEye: ERROR {e}")
        else:
            out.append("ZoomEye: missing key")

        
        if cfg.webcheck_base_url:
            try:
                url = cfg.webcheck_base_url.rstrip("/") + "/api/headers"
                r = requests.get(url, params={"url": "https://example.com"}, timeout=12)
                out.append(f"Web-Check API: HTTP {r.status_code} at {url}")
            except Exception as e:
                out.append(f"Web-Check API: ERROR {e}")

        
        try:
            headers = {"Accept": "application/json"}
            if cfg.nvd_api_key:
                headers["apiKey"] = cfg.nvd_api_key
            r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": "CVE-2021-44228"}, headers=headers, timeout=15)
            out.append(f"NVD: HTTP {r.status_code} (cves/2.0)")
        except Exception as e:
            out.append(f"NVD: ERROR {e}")

        
        if cfg.openai_api_key:
            try:
                from openai import OpenAI
                client = OpenAI(api_key=cfg.openai_api_key)
                resp = client.responses.create(
                    model=cfg.openai_model or "gpt-5",
                    input="Write one word: OK",
                    store=False,
                )
                out.append("OpenAI: OK (responses.create)")
                out.append("  sample: " + (getattr(resp, "output_text", "") or "")[:60])
            except Exception as e:
                out.append(f"OpenAI: ERROR {e}")
        else:
            out.append("OpenAI: missing key")

        self.out.setText("\n".join(out))
