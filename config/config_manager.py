
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "amanscan"
CONFIG_FILE = CONFIG_DIR / "config.json"
HISTORY_DB = CONFIG_DIR / "history.sqlite"

@dataclass
class AppConfig:

    shodan_api_key: str = ""
    zoomeye_api_key: str = ""
    openai_api_key: str = ""
    openai_model: str = "gpt-5"
    github_token: str = ""
    webcheck_base_url: str = "http://127.0.0.1:8080"
    nvd_api_key: str = ""  


    enable_webcheck: bool = True
    enable_shodan: bool = True
    enable_zoomeye: bool = True
    enable_nvd: bool = True
    enable_ai: bool = True


    ui_theme: str = "hud_dark"  


    history_db_path: str = str(HISTORY_DB)

def ensure_config() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        save_config(AppConfig())

def load_config() -> AppConfig:
    ensure_config()
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        base = asdict(AppConfig())
        base.update(data or {})
        return AppConfig(**base)
    except Exception:
        return AppConfig()

def save_config(cfg: AppConfig) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except Exception:
        pass

def mask(s: str) -> str:
    if not s:
        return ""
    if len(s) <= 6:
        return "*" * len(s)
    return s[:3] + "*" * (len(s) - 6) + s[-3:]
