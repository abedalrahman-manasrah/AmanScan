
HUD_DARK_QSS = """
QMainWindow { background: #05070c; }
QWidget { color: #d7e6ff; font-family: Consolas, "Cascadia Mono", "Courier New", monospace; }

/* ✅ Dialogs must match the HUD theme */
QDialog { 
    background: #05070c; 
    border: 2px solid rgba(35, 184, 255, 0.6); 
    border-radius: 14px; 
    box-shadow: 0 0 15px rgba(35, 184, 255, 0.9);
}
QDialog QWidget { color: #d7e6ff; }
QDialog QLabel#TitleLabel { 
    color: #eaf2ff; 
    font-size: 18px; 
    font-weight: 700; 
    text-shadow: 0 0 8px rgba(35, 184, 255, 0.6); 
}
QDialog QLabel#SubTitleLabel { 
    color: rgba(215,230,255,0.75); 
    font-size: 14px; 
    font-weight: 600;
}
QDialog QLabel#DevLabel {
    color: #1ad9f1; 
    font-size: 13px; 
    font-weight: 600; 
    text-align: center;
    padding-top: 8px;
}

QPushButton {
    background: rgba(20, 110, 255, 0.30);
    border: 1px solid rgba(120,180,255,0.35);
    padding: 10px 12px;
    border-radius: 12px;
    font-weight: 700;
    font-size: 14px;
    text-shadow: 0 0 6px rgba(255, 255, 255, 0.4);
}
QPushButton:hover { background: rgba(35, 140, 255, 0.42); }
QPushButton:pressed { background: rgba(35, 140, 255, 0.24); }
QPushButton:disabled { background: rgba(20,110,255,0.12); border-color: rgba(120,180,255,0.12); }

QFrame#HeaderFrame {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #07101f, stop:1 #05070c);
  border: 1px solid rgba(120,180,255,0.22);
  border-radius: 14px;
}

QFrame#Panel {
  background: rgba(9, 15, 28, 0.86);
  border: 1px solid rgba(120,180,255,0.16);
  border-radius: 14px;
}

QFrame#Panel[active="true"] {
  border: 1px solid rgba(35,184,255,0.55);
  background: rgba(9, 15, 28, 0.92);
}

QLineEdit, QPlainTextEdit, QTextEdit, QTextBrowser {
  background: rgba(6, 10, 20, 0.92);
  border: 1px solid rgba(120,180,255,0.18);
  border-radius: 12px;
  padding: 10px;
  selection-background-color: rgba(60, 160, 255, 0.35);
}

QProgressBar {
  background: rgba(6,10,20,0.92);
  border: 1px solid rgba(120,180,255,0.18);
  border-radius: 10px;
  text-align: center;
  height: 18px;
}
QProgressBar::chunk {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
    stop:0 rgba(35,200,255,0.55), stop:1 rgba(35,140,255,0.55));
  border-radius: 10px;
}

QListWidget {
  background: rgba(6,10,20,0.92);
  border: 1px solid rgba(120,180,255,0.18);
  border-radius: 12px;
  padding: 6px;
}
QListWidget::item { padding: 10px; border-radius: 10px; }
QListWidget::item:selected { background: rgba(35,140,255,0.25); border: 1px solid rgba(35,184,255,0.32); }

QComboBox {
  background: rgba(6,10,20,0.92);
  border: 1px solid rgba(120,180,255,0.18);
  border-radius: 12px;
  padding: 8px 10px;
}
QComboBox QAbstractItemView {
  background: rgba(6,10,20,0.98);
  border: 1px solid rgba(120,180,255,0.18);
  selection-background-color: rgba(35,140,255,0.25);
}
"""

BLUE_QSS = """
QMainWindow { background: #0b1220; }
QWidget { color: #e8f0ff; font-family: Arial; }
QDialog { background: #0b1220; }
QLineEdit, QTextEdit, QPlainTextEdit, QTextBrowser {
  background: #0f1b33; border: 1px solid rgba(255,255,255,.08);
  border-radius: 10px; padding: 8px; selection-background-color: #2f6fed;
}
QPushButton {
  background: #2f6fed; border: 0; padding: 10px 12px;
  border-radius: 12px; font-weight: 600;
}
QPushButton:hover { background: #3b7cff; }
QPushButton:disabled { background: rgba(47,111,237,.35); }
QGroupBox {
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 14px; margin-top: 10px; padding: 10px;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #9fb3d1; }
QProgressBar {
  background: #0f1b33; border: 1px solid rgba(255,255,255,.08);
  border-radius: 10px; text-align: center; height: 18px;
}
QProgressBar::chunk { background: #2f6fed; border-radius: 10px; }
"""

def stylesheet_for(theme: str) -> str:
    t = (theme or "").strip().lower()
    if t == "classic_blue":
        return BLUE_QSS
    return HUD_DARK_QSS
