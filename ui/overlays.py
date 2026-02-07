
from __future__ import annotations
from PyQt5 import QtWidgets, QtCore, QtGui

class ScanGridOverlay(QtWidgets.QWidget):
    """
    Overlay HUD grid with subtle animation.
    Put it above main window content.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents, True)
        self.setAttribute(QtCore.Qt.WA_NoSystemBackground, True)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)

        self._enabled = True
        self._offset = 0.0
        self._speed = 0.55  # subtle
        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)  # ~30 FPS

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = bool(enabled)
        self.setVisible(self._enabled)
        self.update()

    def _tick(self):
        if not self._enabled:
            return
        self._offset += self._speed
        if self._offset > 30:
            self._offset = 0.0
        self.update()

    def paintEvent(self, e: QtGui.QPaintEvent):
        if not self._enabled:
            return

        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, False)

        w = self.width()
        h = self.height()

        
        p.fillRect(0, 0, w, h, QtGui.QColor(0, 0, 0, 0))

        grid = 28
        off = int(self._offset)

       
        pen = QtGui.QPen(QtGui.QColor(35, 184, 255, 18))
        pen.setWidth(1)
        p.setPen(pen)

        for x in range(-grid, w + grid, grid):
            p.drawLine(x + off, 0, x + off, h)
        for y in range(-grid, h + grid, grid):
            p.drawLine(0, y + off, w, y + off)

        
        cx, cy = w // 2, h // 2
        pen2 = QtGui.QPen(QtGui.QColor(215, 230, 255, 28))
        pen2.setWidth(1)
        p.setPen(pen2)
        p.drawLine(cx - 70, cy, cx + 70, cy)
        p.drawLine(cx, cy - 70, cx, cy + 70)

        p.end()
