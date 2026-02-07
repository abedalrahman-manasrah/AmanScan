
from __future__ import annotations
from typing import Dict
from PyQt5 import QtGui, QtCore, QtWidgets

_svg_cache: Dict[str, QtGui.QIcon] = {}

def _std(sp: QtWidgets.QStyle.StandardPixmap) -> QtGui.QIcon:
    return QtWidgets.QApplication.style().standardIcon(sp)

def _svg_icon(svg: str, size: int = 20) -> QtGui.QIcon:
    """
    Render SVG string to QIcon.
    MUST be called after QApplication is created.
    If QtSvg is missing, fall back to standard icons.
    """
    try:
        from PyQt5 import QtSvg
        renderer = QtSvg.QSvgRenderer(QtCore.QByteArray(svg.encode("utf-8")))
        pm = QtGui.QPixmap(size, size)
        pm.fill(QtCore.Qt.transparent)
        p = QtGui.QPainter(pm)
        renderer.render(p)
        p.end()
        return QtGui.QIcon(pm)
    except Exception:
        return _std(QtWidgets.QStyle.SP_FileIcon)

_SVGS: Dict[str, str] = {
    "Dashboard": """
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none">
      <path stroke="rgba(215,230,255,0.92)" stroke-width="2"
       d="M4 13h7V4H4v9Zm9 7h7V11h-7v9ZM4 20h7v-5H4v5Zm9-11h7V4h-7v5Z"/>
    </svg>
    """,
    "Scan": """
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none">
      <path stroke="rgba(215,230,255,0.92)" stroke-width="2" d="M12 2v4m0 12v4M2 12h4m12 0h4"/>
      <circle cx="12" cy="12" r="5" stroke="rgba(35,184,255,0.95)" stroke-width="2"/>
    </svg>
    """,
    "Findings": """
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none">
      <path stroke="rgba(215,230,255,0.92)" stroke-width="2" d="M4 5h16v14H4z"/>
      <path stroke="rgba(35,184,255,0.95)" stroke-width="2" d="M7 9h10M7 12h10M7 15h6"/>
    </svg>
    """,
    "Report": """
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none">
      <path stroke="rgba(215,230,255,0.92)" stroke-width="2" d="M6 3h9l3 3v15H6z"/>
      <path stroke="rgba(35,184,255,0.95)" stroke-width="2" d="M9 11h6M9 14h6M9 17h6"/>
    </svg>
    """,
    "Trend": """
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none">
      <path stroke="rgba(215,230,255,0.92)" stroke-width="2" d="M4 19V5"/>
      <path stroke="rgba(215,230,255,0.92)" stroke-width="2" d="M4 19h16"/>
      <path stroke="rgba(35,184,255,0.95)" stroke-width="2" d="M6 15l4-5 4 3 4-6"/>
      <circle cx="10" cy="10" r="1.2" fill="rgba(35,184,255,0.95)"/>
      <circle cx="14" cy="13" r="1.2" fill="rgba(35,184,255,0.95)"/>
      <circle cx="18" cy="7" r="1.2" fill="rgba(35,184,255,0.95)"/>
    </svg>
    """,
    "Settings": """
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none">
      <path stroke="rgba(215,230,255,0.92)" stroke-width="2" d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/>
      <path stroke="rgba(35,184,255,0.95)" stroke-width="2"
        d="M19.4 15a7.7 7.7 0 0 0 .1-2l2-1.2-2-3.4-2.3.6a7.9 7.9 0 0 0-1.7-1L15 5.6h-6L8.5 7.9a7.9 7.9 0 0 0-1.7 1l-2.3-.6-2 3.4L4.5 13a7.7 7.7 0 0 0 .1 2L2.6 16.2l2 3.4 2.3-.6c.5.4 1.1.8 1.7 1L9 22.4h6l.5-2.3c.6-.2 1.2-.6 1.7-1l2.3.6 2-3.4-2.1-1.3Z"/>
    </svg>
    """,
}

_FALLBACKS: Dict[str, QtWidgets.QStyle.StandardPixmap] = {
    "Dashboard": QtWidgets.QStyle.SP_DesktopIcon,
    "Scan": QtWidgets.QStyle.SP_BrowserReload,
    "Findings": QtWidgets.QStyle.SP_MessageBoxInformation,
    "Report": QtWidgets.QStyle.SP_FileDialogDetailedView,
    "Trend": QtWidgets.QStyle.SP_ComputerIcon,
    "Settings": QtWidgets.QStyle.SP_FileDialogContentsView,
}

def get_icon(name: str, size: int = 20) -> QtGui.QIcon:
    """
    Lazy-load icon (safe: only after QApplication exists).
    """
    key = f"{name}:{size}"
    if key in _svg_cache:
        return _svg_cache[key]

    svg = _SVGS.get(name)
    if svg:
        icon = _svg_icon(svg, size=size)
    else:
        icon = _std(_FALLBACKS.get(name, QtWidgets.QStyle.SP_FileIcon))

    _svg_cache[key] = icon
    return icon
