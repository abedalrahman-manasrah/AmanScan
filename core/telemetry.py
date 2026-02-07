
from __future__ import annotations
from typing import Any, Dict, Optional
import sqlite3
import time
from pathlib import Path

def ensure_db(db_path: str) -> None:
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    try:
        con.execute("""
        CREATE TABLE IF NOT EXISTS api_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            source TEXT NOT NULL,
            action TEXT NOT NULL,
            ok INTEGER NOT NULL,
            http_status INTEGER,
            err TEXT,
            meta TEXT
        )
        """)
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
        con.commit()
    finally:
        con.close()

def log_api_event(db_path: str, source: str, action: str, ok: bool,
                  http_status: Optional[int] = None, err: str = "", meta: str = "") -> None:
    ensure_db(db_path)
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            "INSERT INTO api_events(ts,source,action,ok,http_status,err,meta) VALUES (?,?,?,?,?,?,?)",
            (int(time.time()), source, action, 1 if ok else 0, http_status, (err or "")[:500], (meta or "")[:2000])
        )
        con.commit()
    finally:
        con.close()

def log_scan_summary(db_path: str, summary: Dict[str, Any]) -> None:
    ensure_db(db_path)
    con = sqlite3.connect(db_path)
    try:
        con.execute("""
        INSERT INTO scan_history(
          ts,target,host,ip,exposure_hint,risk_overall,top_cvss,kev_count,
          critical_count,high_count,medium_count,low_count,info_count
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            int(time.time()),
            summary.get("target",""),
            summary.get("host",""),
            summary.get("ip",""),
            int(summary.get("exposure_hint",0) or 0),
            int(summary.get("risk_overall",0) or 0),
            float(summary.get("top_cvss",0.0) or 0.0),
            int(summary.get("kev_count",0) or 0),
            int(summary.get("Critical",0) or 0),
            int(summary.get("High",0) or 0),
            int(summary.get("Medium",0) or 0),
            int(summary.get("Low",0) or 0),
            int(summary.get("Info",0) or 0),
        ))
        con.commit()
    finally:
        con.close()
