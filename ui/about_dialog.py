
from __future__ import annotations
from PyQt5 import QtWidgets, QtCore

DEV_1 = "Abed Alrahman Manasrah"
DEV_2 = "Abdulhamid zaro"

class AboutDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, version: str = "1.0.0"):
        super().__init__(parent)
        self.setWindowTitle("About AmanScan")
        self.setModal(True)
        self.resize(520, 320)

       
        app = QtWidgets.QApplication.instance()
        if app is not None:
            self.setStyleSheet(app.styleSheet())

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        
        title = QtWidgets.QLabel("AmanScan — Security Exposure Intelligence")
        title.setObjectName("TitleLabel")

        sub = QtWidgets.QLabel(
            "Passive OSINT tool for exposure awareness and defensive reporting.\n"
            "No exploitation instructions are provided."
        )
        sub.setObjectName("SubTitleLabel")
        sub.setWordWrap(True)

        info = QtWidgets.QLabel(
            f"<b>Version:</b> {version}<br>"
            f"<b>Developers:</b><br>"
            f"<span style='font-weight:600; color:#1ad9f1;'>{DEV_1}</span><br>"
            f"<span style='font-weight:600; color:#1ad9f1;'>{DEV_2}</span><br>"
        )
        info.setObjectName("SubTitleLabel")
        info.setTextFormat(QtCore.Qt.RichText)

       
        btns = QtWidgets.QHBoxLayout()
        btns.addStretch(1)
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btns.addWidget(close_btn)

        layout.addWidget(title)
        layout.addWidget(sub)
        layout.addWidget(info)
        layout.addStretch(1)
        layout.addLayout(btns)
